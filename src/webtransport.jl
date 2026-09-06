"""
A WebTransport session over HTTP/3. `connect(url)` does the H3 handshake, sends the Extended
CONNECT, and returns a `Session` with Channels for incoming streams and datagrams.
"""
module WebTransport

using ..Quic, ..H3
using ..Quic: readn

export Session, connect, open_stream, send_datagram, datagrams, incoming_streams, close_write, reset

mutable struct Session
    conn::Quic.Connection
    id::Int                             # the CONNECT stream's id = session id
    request::Quic.Stream                # the CONNECT stream (carries capsules afterwards)
    streams::Channel{Quic.Stream}       # streams the server opened for this session, header stripped
    datagrams::Channel{Vector{UInt8}}
    status::String
    pump::Task
end

"""
    connect(url; verify = true, timeout = 5.0, kw...) -> Session

`url` is `https://host:port/path`. `verify = false` accepts a self-signed certificate.
Throws if the server answers anything but 200.
"""
function connect(url::AbstractString; verify = true, timeout = 5.0, kw...)
    m = match(r"^https://([^/:]+)(?::(\d+))?(/.*)?$", url)
    m === nothing && throw(ArgumentError("url must look like https://host:port/path"))
    host = m[1]; port = m[2] === nothing ? 443 : parse(Int, m[2]); path = something(m[3], "/")
    authority = m[2] === nothing ? host : "$host:$port"

    conn = Quic.connect(host, port; alpn = "h3", verify, timeout, kw...)
    # Our three unidirectional streams: control (with SETTINGS), QPACK encoder, QPACK decoder.
    ctrl = Quic.open_stream(conn; unidirectional = true)
    write(ctrl, vcat(H3.encode_varint(H3.STREAM_CONTROL), H3.client_settings()))
    write(Quic.open_stream(conn; unidirectional = true), H3.encode_varint(H3.STREAM_QPACK_ENCODER))
    write(Quic.open_stream(conn; unidirectional = true), H3.encode_varint(H3.STREAM_QPACK_DECODER))

    # Extended CONNECT on a bidi stream. Its id is the session id.
    req = Quic.open_stream(conn)
    write(req, H3.frame(H3.FRAME_HEADERS, H3.encode_connect(authority, path)))
    status = read_status(req, timeout)
    status == "200" || (close(conn); error("WebTransport CONNECT $path: $status"))

    sess = Session(conn, req.id, req, Channel{Quic.Stream}(Inf), Channel{Vector{UInt8}}(Inf), status,
                   Task(() -> nothing))
    sess.pump = Threads.@spawn pump(sess)
    sess
end

# Read frames on the request stream until a HEADERS frame yields a :status.
function read_status(req::Quic.Stream, timeout)
    buf = UInt8[]
    deadline = time() + timeout
    while time() < deadline
        f = H3.parse_frame(buf)
        if f !== nothing
            type, payload, rest = f
            buf = rest
            if type == H3.FRAME_HEADERS
                st = H3.decode_status(payload)
                return st === nothing ? "?" : st
            end
            continue
        end
        ev = Quic.wait_for(req.inbox, deadline - time())
        ev === nothing && break
        ev[1] == :data && append!(buf, ev[2])
        ev[1] == :reset && error("CONNECT stream reset: $(ev[2])")
        ev[1] == :closed && break
    end
    "?"
end

# Route connection events: peer streams get classified by their first bytes; datagrams get
# their quarter-stream-id stripped. Server control/QPACK streams are drained and ignored.
function pump(sess::Session)
    for ev in sess.conn.events
        try
            if ev[1] == :stream
                Threads.@spawn classify(sess, ev[2])
            elseif ev[1] == :datagram
                d = H3.parse_datagram(ev[2])
                d !== nothing && d[1] == sess.id && put!(sess.datagrams, d[2])
            elseif ev[1] == :shutdown
                break
            end
        catch e
            @error "hayate pump" exception = (e, catch_backtrace())
        end
    end
    close(sess.streams); close(sess.datagrams)
end

function classify(sess::Session, s::Quic.Stream)
    buf = UInt8[]
    while true
        bytes, fin = read(s)
        append!(buf, bytes)
        r = H3.decode_varint(buf)
        if r !== nothing
            type, i = r
            if type == H3.STREAM_WT_UNI || type == H3.FRAME_WT_BIDI
                r2 = H3.decode_varint(buf, i)
                if r2 !== nothing
                    sid, j = r2
                    if sid == sess.id
                        rest = buf[j:end]
                        isempty(rest) || pushfirst_data!(s, rest, fin)
                        put!(sess.streams, s)
                    else
                        close(s)
                    end
                    return
                end
            else
                drain(s); return                              # control / qpack / unknown: read and forget
            end
        end
        fin && return
    end
end

# Put bytes we already pulled off a stream back at the front of its inbox.
function pushfirst_data!(s::Quic.Stream, bytes, fin)
    rest = Any[]
    while isready(s.inbox); push!(rest, take!(s.inbox)); end
    put!(s.inbox, (:data, bytes, fin))
    for x in rest; put!(s.inbox, x); end
end

function drain(s::Quic.Stream)
    while true
        _, fin = read(s)
        fin && return
    end
end

"Open a WebTransport stream for this session. The header is written for you."
function open_stream(sess::Session; unidirectional::Bool = false)
    s = Quic.open_stream(sess.conn; unidirectional)
    write(s, H3.wt_stream_header(sess.id, !unidirectional))
    s
end

send_datagram(sess::Session, data::AbstractVector{UInt8}) = Quic.send_datagram(sess.conn, H3.datagram(sess.id, data))
send_datagram(sess::Session, s::AbstractString) = send_datagram(sess, Vector{UInt8}(codeunits(s)))

"Channel of datagrams from the server (payload only)."
datagrams(sess::Session) = sess.datagrams
"Channel of streams the server opened for this session, header already stripped."
incoming_streams(sess::Session) = sess.streams

Base.close(sess::Session) = close(sess.conn)

end # module WebTransport
