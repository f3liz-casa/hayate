"""
QUIC connections and streams with a Julia face. A `Stream` is an `IO`: `read`, `write`,
`eof`, `closewrite`, `close` all mean what they mean elsewhere. Events from msquic's threads
land in Channels, and the IO methods block on those.
"""
module Quic

using ..MsQuic
using ..MsQuic: HQUIC, Status, STATUS_SUCCESS, root!, unroot!, event_type, payload

export Connection, Stream, connect, openstream, senddatagram, datagrams, streams, abort, StreamReset, ConnectError

struct StreamReset <: Exception
    id::Int
    code::Int
end
Base.showerror(io::IO, e::StreamReset) = print(io, "stream ", e.id, " reset by peer (code ", e.code, ")")

struct ConnectError <: Exception
    msg::String
end
Base.showerror(io::IO, e::ConnectError) = print(io, "connect: ", e.msg)

# --- Types ---

# What a stream's callback hands to its reader.
struct Chunk
    bytes::Vector{UInt8}
    fin::Bool
end
struct Reset
    code::Int
end
const StreamMsg = Union{Chunk,Reset}

# What a connection's callback hands to whoever is waiting on it.
struct Connected end
struct Shutdown
    by::Symbol                           # :transport or :peer
    status::UInt32
    code::UInt64
end
const ConnMsg = Union{Connected,Shutdown}

"""
One QUIC stream, as an `IO`. Bytes arrive from msquic as `Chunk`s on `inbox`; `read` drains
them through `rbuf`. `eof` is true once the peer's FIN has been consumed.
"""
mutable struct Stream <: IO
    handle::HQUIC
    id::Int                              # QUIC stream id; -1 until START_COMPLETE
    unidirectional::Bool
    inbox::Channel{StreamMsg}
    started::Channel{Int}
    rbuf::Vector{UInt8}
    rpos::Int
    fin::Bool                            # peer's FIN consumed into rbuf
    open::Bool
end
Stream(handle, unidirectional) = Stream(handle, -1, unidirectional, Channel{StreamMsg}(Inf), Channel{Int}(1), UInt8[], 1, false, true)

mutable struct Connection
    handle::HQUIC
    config::HQUIC
    events::Channel{ConnMsg}
    streams::Channel{Stream}             # streams the peer opened
    datagrams::Channel{Vector{UInt8}}
    done::Channel{Nothing}
    open::Bool
    datagram_max::Int
end
Connection(config) = Connection(C_NULL, config, Channel{ConnMsg}(Inf), Channel{Stream}(Inf), Channel{Vector{UInt8}}(Inf), Channel{Nothing}(1), true, 0)

Base.show(io::IO, s::Stream) = print(io, "Quic.Stream(id=", s.id, s.unidirectional ? ", uni" : ", bidi", s.open ? "" : ", closed", ")")
Base.show(io::IO, c::Connection) = print(io, "Quic.Connection(", c.open ? "open" : "closed", ")")

# --- Callbacks: copy, put!, return. Nothing else happens on msquic's threads. ---

function on_connection(::HQUIC, ctx::Ptr{Cvoid}, ev::Ptr{Cvoid})::Status
    conn = unsafe_pointer_to_objref(ctx)::Connection
    t = MsQuic.ConnectionEvent(event_type(ev))
    try
        if t == MsQuic.CONNECTED
            put!(conn.events, Connected())
        elseif t == MsQuic.PEER_STREAM_STARTED
            e = payload(MsQuic.EvPeerStreamStarted, ev)
            s = root!(Stream(e.Stream, e.Flags & MsQuic.STREAM_OPEN_UNIDIRECTIONAL != 0))
            MsQuic.set_callback_handler(e.Stream, MsQuic.STREAM_CB[], pointer_from_objref(s))
            put!(conn.streams, s)
        elseif t == MsQuic.DATAGRAM_RECEIVED
            put!(conn.datagrams, MsQuic.copy_buffers(payload(MsQuic.EvDatagramReceived, ev).Buffer, 1))
        elseif t == MsQuic.DATAGRAM_STATE_CHANGED
            conn.datagram_max = Int(payload(MsQuic.EvDatagramStateChanged, ev).MaxSendLength)
        elseif t == MsQuic.DATAGRAM_SEND_STATE_CHANGED
            # SENT is followed by ACKNOWLEDGED or LOST for the same context. Unroot only once,
            # at a terminal state; the pointer must still be valid until then.
            e = payload(MsQuic.EvDatagramSendState, ev)
            MsQuic.dgram_terminal(e.State) && unroot!(e.ClientContext)
        elseif t == MsQuic.SHUTDOWN_INITIATED_BY_TRANSPORT
            e = payload(MsQuic.EvShutdownByTransport, ev)
            put!(conn.events, Shutdown(:transport, e.Status, e.ErrorCode))
        elseif t == MsQuic.SHUTDOWN_INITIATED_BY_PEER
            put!(conn.events, Shutdown(:peer, 0, payload(MsQuic.EvShutdownByPeer, ev).ErrorCode))
        elseif t == MsQuic.SHUTDOWN_COMPLETE
            conn.open = false
            isready(conn.done) || put!(conn.done, nothing)
            close(conn.events); close(conn.streams); close(conn.datagrams)
        end
    catch e
        @error "hayate connection callback" exception = (e, catch_backtrace())
    end
    STATUS_SUCCESS
end

function on_stream(::HQUIC, ctx::Ptr{Cvoid}, ev::Ptr{Cvoid})::Status
    s = unsafe_pointer_to_objref(ctx)::Stream
    t = MsQuic.StreamEvent(event_type(ev))
    try
        if t == MsQuic.START_COMPLETE
            s.id = Int(payload(MsQuic.EvStartComplete, ev).ID)
            isready(s.started) || put!(s.started, s.id)
        elseif t == MsQuic.RECEIVE
            e = payload(MsQuic.EvReceive, ev)
            put!(s.inbox, Chunk(MsQuic.copy_buffers(e.Buffers, e.BufferCount), e.Flags & MsQuic.RECEIVE_FLAG_FIN != 0))
        elseif t == MsQuic.SEND_COMPLETE
            unroot!(payload(MsQuic.EvSendComplete, ev).ClientContext)
        elseif t == MsQuic.PEER_SEND_SHUTDOWN
            put!(s.inbox, Chunk(UInt8[], true))
        elseif t == MsQuic.PEER_SEND_ABORTED
            put!(s.inbox, Reset(Int(payload(MsQuic.EvPeerSendAborted, ev).ErrorCode)))
        elseif t == MsQuic.STREAM_SHUTDOWN_COMPLETE
            s.open = false
            close(s.inbox)
            MsQuic.stream_close(s.handle)      # allowed from inside this event; never touched again
            unroot!(s)
        end
    catch e
        @error "hayate stream callback" exception = (e, catch_backtrace())
    end
    STATUS_SUCCESS
end

function __init__()
    MsQuic.CONNECTION_CB[] = @cfunction(on_connection, Status, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}))
    MsQuic.STREAM_CB[] = @cfunction(on_stream, Status, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}))
end

# --- Waiting on a Channel with a deadline ---

"`take!` within `timeout` seconds, or `nothing`."
function take_within(ch::Channel, timeout::Real)
    timedwait(() -> isready(ch) || !isopen(ch), float(timeout); pollint = 0.002)
    isready(ch) ? take!(ch) : nothing
end

# --- Connection ---

"""
    connect(host, port; alpn = "h3", verify = true, timeout = 5.0, settings...) -> Connection

Open a QUIC connection and wait for the handshake. `verify = false` accepts any certificate
(self-signed servers in development). Remaining keywords go to `MsQuic.settings`.
"""
function connect(host::AbstractString, port::Integer; alpn = "h3", verify = true, timeout = 5.0, kw...)
    cfg = MsQuic.configuration_open(String(alpn), MsQuic.settings(; kw...))
    MsQuic.configuration_load_credential(cfg; verify)
    conn = root!(Connection(cfg))
    conn.handle = MsQuic.connection_open(pointer_from_objref(conn))
    MsQuic.connection_start(conn.handle, cfg, String(host), port)
    ev = take_within(conn.events, timeout)
    ev isa Connected && return conn
    close(conn)
    throw(ConnectError(ev === nothing ? "timeout after $(timeout)s" : describe(ev)))
end

describe(s::Shutdown) = s.by == :transport ? "transport shut down (status 0x$(string(s.status, base = 16)), code $(s.code))" :
                                             "peer shut down (code $(s.code))"

"Streams the peer opens, as a Channel."
streams(conn::Connection) = conn.streams
"Datagrams from the peer, as a Channel of byte vectors."
datagrams(conn::Connection) = conn.datagrams

"Open a stream. Returns once msquic has assigned its id."
function openstream(conn::Connection; unidirectional::Bool = false, timeout = 5.0)
    s = root!(Stream(C_NULL, unidirectional))
    s.handle = MsQuic.stream_open(conn.handle, unidirectional ? MsQuic.STREAM_OPEN_UNIDIRECTIONAL : UInt32(0), pointer_from_objref(s))
    MsQuic.stream_start(s.handle)
    take_within(s.started, timeout) === nothing && throw(ConnectError("stream did not start within $(timeout)s"))
    s
end

senddatagram(conn::Connection, data::AbstractVector{UInt8}) = MsQuic.datagram_send(conn.handle, Vector{UInt8}(data))
senddatagram(conn::Connection, str::AbstractString) = senddatagram(conn, codeunits(str))

Base.isopen(conn::Connection) = conn.open

"Shut the connection down and release the handle. Blocks until msquic has finished."
function Base.close(conn::Connection; timeout = 2.0)
    conn.handle == C_NULL && return nothing
    conn.open && MsQuic.connection_shutdown(conn.handle)
    take_within(conn.done, timeout)
    MsQuic.connection_close(conn.handle)
    conn.handle = C_NULL
    MsQuic.configuration_close(conn.config)
    unroot!(conn)
    nothing
end

# --- Stream as IO ---

# Pull the next chunk from msquic into rbuf. Returns false if there is nothing more to come.
function pull!(s::Stream)
    s.fin && return false
    (isopen(s.inbox) || isready(s.inbox)) || (s.fin = true; return false)
    msg = try take!(s.inbox) catch; Chunk(UInt8[], true) end
    if msg isa Reset
        s.fin = true
        throw(StreamReset(s.id, msg.code))
    end
    if s.rpos > length(s.rbuf)
        s.rbuf = msg.bytes; s.rpos = 1     # the chunk is ours; no copy
    else
        append!(s.rbuf, msg.bytes)
    end
    msg.fin && (s.fin = true)
    true
end

Base.bytesavailable(s::Stream) = length(s.rbuf) - s.rpos + 1
function Base.eof(s::Stream)
    while bytesavailable(s) == 0
        pull!(s) || return true
    end
    false
end
function Base.read(s::Stream, ::Type{UInt8})
    eof(s) && throw(EOFError())
    b = s.rbuf[s.rpos]; s.rpos += 1
    b
end
function Base.unsafe_read(s::Stream, p::Ptr{UInt8}, n::UInt)
    got = 0
    while got < n
        eof(s) && throw(EOFError())
        take = min(Int(n) - got, bytesavailable(s))
        unsafe_copyto!(p + got, pointer(s.rbuf, s.rpos), take)
        s.rpos += take; got += take
    end
    nothing
end
"Whatever has arrived, without waiting for more than one chunk."
function Base.readavailable(s::Stream)
    bytesavailable(s) == 0 && pull!(s)
    out = s.rbuf[s.rpos:end]
    s.rpos = length(s.rbuf) + 1
    out
end

# One copy per write: msquic reads the bytes later, from its own threads, and the caller is
# free to reuse its buffer the moment `write` returns. That is the IO contract; we keep it.
function Base.unsafe_write(s::Stream, p::Ptr{UInt8}, n::UInt)
    buf = Vector{UInt8}(undef, n)
    unsafe_copyto!(pointer(buf), p, n)
    MsQuic.stream_send(s.handle, buf)
    Int(n)
end
Base.write(s::Stream, b::UInt8) = write(s, UInt8[b])

Base.isopen(s::Stream) = s.open
Base.isreadable(s::Stream) = s.open && !s.fin
Base.iswritable(s::Stream) = s.open
"Send FIN. The peer sees end of stream; we can still read."
Base.closewrite(s::Stream) = (MsQuic.stream_shutdown(s.handle, MsQuic.STREAM_SHUTDOWN_GRACEFUL); nothing)
"Abort both directions with an application error code."
abort(s::Stream, code::Integer = 0) = (s.open && MsQuic.stream_shutdown(s.handle, MsQuic.STREAM_SHUTDOWN_ABORT, code); nothing)
Base.close(s::Stream) = abort(s)

end # module Quic
