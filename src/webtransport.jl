"""
A WebTransport session over HTTP/3. `connect(url)` does the H3 handshake, sends the Extended
CONNECT, and returns a `Session`. Streams are `IO`s; datagrams and incoming streams are
Channels.
"""
module WebTransport

using ..Quic, ..H3
using ..Quic: take_within

export Session, connect, openstream, senddatagram, datagrams, streams, abort, RejectedError

mutable struct Session
    conn::Quic.Connection
    id::Int                              # the CONNECT stream's id is the session id
    request::Quic.Stream                 # the CONNECT stream; carries capsules afterwards
    streams::Channel{Quic.Stream}        # streams the server opened for this session, header stripped
    datagrams::Channel{Vector{UInt8}}    # payloads only
    url::String
    pump::Task
end
Base.show(io::IO, s::Session) = print(io, "WebTransport.Session(", s.url, ", id=", s.id, isopen(s) ? "" : ", closed", ")")

"The server answered the CONNECT with something other than 200."
struct RejectedError <: Exception
    url::String
    status::String
end
Base.showerror(io::IO, e::RejectedError) = print(io, "WebTransport CONNECT ", e.url, " rejected: ", e.status)

"""
    connect(url; verify = true, timeout = 5.0, settings...) -> Session
    connect(f, url; ...)

`url` is `https://host:port/path`. `verify = false` accepts a self-signed certificate. Throws
`RejectedError` if the server answers anything but 200, `Quic.ConnectError` if QUIC fails. The `do` form closes the session
when `f` returns.
"""
function connect(url::AbstractString; verify = true, timeout = 5.0, kw...)
    m = match(r"^https://([^/:]+)(?::(\d+))?(/.*)?$", url)
    m === nothing && throw(ArgumentError("url must look like https://host:port/path, got $url"))
    host = m[1]; port = m[2] === nothing ? 443 : parse(Int, m[2]); path = something(m[3], "/")
    authority = m[2] === nothing ? host : "$host:$port"

    conn = Quic.connect(host, port; alpn = "h3", verify, timeout, kw...)
    try
        # Our three unidirectional streams: control (with SETTINGS), QPACK encoder, QPACK decoder.
        write(Quic.openstream(conn; unidirectional = true), vcat(H3.encode_varint(H3.STREAM_CONTROL), H3.client_settings()))
        write(Quic.openstream(conn; unidirectional = true), H3.encode_varint(H3.STREAM_QPACK_ENCODER))
        write(Quic.openstream(conn; unidirectional = true), H3.encode_varint(H3.STREAM_QPACK_DECODER))

        # Extended CONNECT on a bidi stream. Its id is the session id.
        req = Quic.openstream(conn)
        write(req, H3.frame(H3.FRAME_HEADERS, H3.encode_connect(authority, path)))
        status = read_status(req, timeout)
        status == "200" || throw(RejectedError(String(url), status))

        sess = Session(conn, req.id, req, Channel{Quic.Stream}(Inf), Channel{Vector{UInt8}}(Inf), String(url), Task(() -> nothing))
        sess.pump = Threads.@spawn pump(sess)
        sess
    catch
        close(conn)
        rethrow()
    end
end

function connect(f, url::AbstractString; kw...)
    s = connect(url; kw...)
    try
        f(s)
    finally
        close(s)
    end
end

# Read frames on the request stream until a HEADERS frame yields a :status.
function read_status(req::Quic.Stream, timeout)
    buf = UInt8[]
    deadline = time() + timeout
    while time() < deadline
        f = H3.parse_frame(buf)
        if f !== nothing
            type, fpayload, rest = f
            buf = rest
            type == H3.FRAME_HEADERS && return something(H3.decode_status(fpayload), "?")
            continue
        end
        chunk = readavailable(req)
        isempty(chunk) && eof(req) && return "closed before a response"
        append!(buf, chunk)
    end
    "no response within $(timeout)s"
end

# Route what the connection delivers: peer streams get classified by their first bytes,
# datagrams get their quarter-stream-id stripped. Anything for another session is dropped.
function pump(sess::Session)
    @sync begin
        Threads.@spawn for s in Quic.streams(sess.conn)
            Threads.@spawn try classify(sess, s) catch e; @error "hayate classify" exception = (e, catch_backtrace()) end
        end
        Threads.@spawn for d in Quic.datagrams(sess.conn)
            p = H3.parse_datagram(d)
            p !== nothing && p[1] == sess.id && put!(sess.datagrams, p[2])
        end
    end
    close(sess.streams); close(sess.datagrams)
end

# Read enough of a peer stream to know what it is. WebTransport streams for this session go
# to `streams`; the server's control and QPACK streams are drained and forgotten.
function classify(sess::Session, s::Quic.Stream)
    head = UInt8[]
    while !eof(s)
        push!(head, read(s, UInt8))
        r = H3.decode_varint(head)
        r === nothing && continue
        type, i = r
        if type == H3.STREAM_WT_UNI || type == H3.FRAME_WT_BIDI
            r2 = H3.decode_varint(head, i)
            r2 === nothing && continue
            r2[1] == sess.id ? put!(sess.streams, s) : abort(s)
            return
        else
            while !eof(s); readavailable(s); end
            return
        end
    end
end

"Open a WebTransport stream on this session. The header is written for you."
function openstream(sess::Session; unidirectional::Bool = false)
    s = Quic.openstream(sess.conn; unidirectional)
    write(s, H3.wt_stream_header(sess.id, !unidirectional))
    s
end

senddatagram(sess::Session, data::AbstractVector{UInt8}) = Quic.senddatagram(sess.conn, H3.datagram(sess.id, data))
senddatagram(sess::Session, str::AbstractString) = senddatagram(sess, codeunits(str))

"Datagrams from the server for this session, as a Channel of payloads."
datagrams(sess::Session) = sess.datagrams
"Streams the server opened for this session, as a Channel. Headers already stripped."
streams(sess::Session) = sess.streams

Base.isopen(sess::Session) = isopen(sess.conn)
Base.close(sess::Session) = close(sess.conn)

end # module WebTransport
