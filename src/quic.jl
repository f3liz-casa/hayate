"""
QUIC connections and streams with a Julia face. Events from msquic's threads land in
Channels; the API here blocks on those Channels, so ordinary Julia tasks can `read` and
`write` streams without knowing about callbacks.
"""
module Quic

using ..MsQuic
using ..MsQuic: HQUIC, Status, STATUS_SUCCESS, root!, unroot!

export Connection, Stream, connect, open_stream, send_datagram, close_write, reset

mutable struct Stream
    handle::HQUIC
    id::Int                         # QUIC stream id (-1 until START_COMPLETE / peer start)
    unidirectional::Bool
    inbox::Channel{Any}             # (:data, bytes, fin) | (:reset, code) | (:closed,)
    started::Channel{Int}           # stream id, once
    open::Bool
    conn                            # ::Connection
end

mutable struct Connection
    handle::HQUIC
    config::HQUIC
    events::Channel{Any}            # (:connected,) | (:stream, Stream) | (:datagram, bytes) | (:shutdown, why)
    done::Channel{Nothing}          # SHUTDOWN_COMPLETE, once
    open::Bool
    datagram_max::Int
end

# --- The two callbacks. Copy, put!, return. Nothing else. ---

function on_connection(h::HQUIC, ctx::Ptr{Cvoid}, ev::Ptr{Cvoid})::Status
    conn = unsafe_pointer_to_objref(ctx)::Connection
    t = unsafe_load(Ptr{UInt32}(ev))
    try
        if t == MsQuic.CONN_CONNECTED
            put!(conn.events, (:connected,))
        elseif t == MsQuic.CONN_PEER_STREAM_STARTED
            sh = unsafe_load(Ptr{HQUIC}(ev + 8))
            flags = unsafe_load(Ptr{UInt32}(ev + 16))
            s = Stream(sh, -1, flags & MsQuic.STREAM_OPEN_UNIDIRECTIONAL != 0,
                       Channel{Any}(Inf), Channel{Int}(1), true, conn)
            root!(s)
            MsQuic.set_callback_handler(sh, MsQuic.STREAM_CB[], pointer_from_objref(s))
            put!(conn.events, (:stream, s))
        elseif t == MsQuic.CONN_DATAGRAM_RECEIVED
            buf = unsafe_load(Ptr{Ptr{UInt8}}(ev + 8))
            put!(conn.events, (:datagram, MsQuic.copy_buffers(buf, 1)))
        elseif t == MsQuic.CONN_DATAGRAM_STATE_CHANGED
            conn.datagram_max = Int(unsafe_load(Ptr{UInt16}(ev + 10)))
        elseif t == MsQuic.CONN_DATAGRAM_SEND_STATE_CHANGED
            # ClientContext at +8 is our Send; msquic is done with it (state is terminal or not,
            # but the bytes were copied at send time for datagrams). Unroot on any state ≥ sent.
            p = unsafe_load(Ptr{Ptr{Cvoid}}(ev + 8))
            p == C_NULL || unroot!(unsafe_pointer_to_objref(p))
        elseif t == MsQuic.CONN_SHUTDOWN_BY_TRANSPORT
            st = unsafe_load(Ptr{UInt32}(ev + 8)); code = unsafe_load(Ptr{UInt64}(ev + 16))
            put!(conn.events, (:shutdown, (:transport, st, code)))
        elseif t == MsQuic.CONN_SHUTDOWN_BY_PEER
            put!(conn.events, (:shutdown, (:peer, unsafe_load(Ptr{UInt64}(ev + 8)))))
        elseif t == MsQuic.CONN_SHUTDOWN_COMPLETE
            conn.open = false
            isready(conn.done) || put!(conn.done, nothing)
            close(conn.events)
        end
    catch e
        @error "hayate connection callback" exception = (e, catch_backtrace())
    end
    STATUS_SUCCESS
end

function on_stream(h::HQUIC, ctx::Ptr{Cvoid}, ev::Ptr{Cvoid})::Status
    s = unsafe_pointer_to_objref(ctx)::Stream
    t = unsafe_load(Ptr{UInt32}(ev))
    try
        if t == MsQuic.STREAM_START_COMPLETE
            s.id = Int(unsafe_load(Ptr{UInt64}(ev + 16)))
            isready(s.started) || put!(s.started, s.id)
        elseif t == MsQuic.STREAM_RECEIVE
            buffers = unsafe_load(Ptr{Ptr{UInt8}}(ev + 24))
            count = unsafe_load(Ptr{UInt32}(ev + 32))
            flags = unsafe_load(Ptr{UInt32}(ev + 36))
            bytes = MsQuic.copy_buffers(buffers, count)
            put!(s.inbox, (:data, bytes, flags & MsQuic.RECEIVE_FLAG_FIN != 0))
        elseif t == MsQuic.STREAM_SEND_COMPLETE
            p = unsafe_load(Ptr{Ptr{Cvoid}}(ev + 16))
            p == C_NULL || unroot!(unsafe_pointer_to_objref(p))
        elseif t == MsQuic.STREAM_PEER_SEND_SHUTDOWN
            put!(s.inbox, (:data, UInt8[], true))
        elseif t == MsQuic.STREAM_PEER_SEND_ABORTED
            put!(s.inbox, (:reset, Int(unsafe_load(Ptr{UInt64}(ev + 8)))))
        elseif t == MsQuic.STREAM_SHUTDOWN_COMPLETE
            s.open = false
            put!(s.inbox, (:closed,))
            close(s.inbox)
            # Allowed from inside this event, and the handle is never touched again.
            MsQuic.stream_close(s.handle)
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

# --- Connection ---

"""
    connect(host, port; alpn = "h3", verify = true, timeout = 5.0, kw...) -> Connection

Open a QUIC connection and wait for the handshake. `verify = false` accepts any certificate
(for self-signed servers in development). Keyword arguments pass to `MsQuic.settings`.
"""
function connect(host::AbstractString, port::Integer; alpn = "h3", verify = true, timeout = 5.0, kw...)
    cfg = MsQuic.configuration_open(String(alpn), MsQuic.settings(; kw...))
    MsQuic.configuration_load_credential(cfg, MsQuic.credential(; verify))
    conn = Connection(C_NULL, cfg, Channel{Any}(Inf), Channel{Nothing}(1), true, 0)
    root!(conn)
    conn.handle = MsQuic.connection_open(pointer_from_objref(conn))
    MsQuic.connection_start(conn.handle, cfg, String(host), port)
    ev = wait_for(conn.events, timeout)
    ev == (:connected,) || (close(conn); error("connect: $(ev === nothing ? "timeout" : ev)"))
    conn
end

function wait_for(ch::Channel, timeout)
    t = Timer(timeout)
    try
        while isopen(ch) || isready(ch)
            isready(ch) && return take!(ch)
            isopen(t) || return nothing
            sleep(0.005)
        end
        nothing
    finally
        close(t)
    end
end

"Open a stream we initiate. Returns once msquic has assigned its id."
function open_stream(conn::Connection; unidirectional::Bool = false, timeout = 5.0)
    s = Stream(C_NULL, -1, unidirectional, Channel{Any}(Inf), Channel{Int}(1), true, conn)
    root!(s)
    flags = unidirectional ? MsQuic.STREAM_OPEN_UNIDIRECTIONAL : UInt32(0)
    s.handle = MsQuic.stream_open(conn.handle, flags, pointer_from_objref(s))
    MsQuic.stream_start(s.handle)
    id = wait_for(s.started, timeout)
    id === nothing && error("open_stream: no START_COMPLETE")
    s
end

send_datagram(conn::Connection, data::AbstractVector{UInt8}) = MsQuic.datagram_send(conn.handle, Vector{UInt8}(data))

"Shut the connection down and release the handle. Blocks until msquic has finished."
function Base.close(conn::Connection; timeout = 2.0)
    conn.handle == C_NULL && return
    conn.open && MsQuic.connection_shutdown(conn.handle)
    wait_for(conn.done, timeout)
    MsQuic.connection_close(conn.handle)
    conn.handle = C_NULL
    MsQuic.configuration_close(conn.config)
    unroot!(conn)
    nothing
end

# --- Stream ---

Base.write(s::Stream, data::AbstractVector{UInt8}; fin::Bool = false) = MsQuic.stream_send(s.handle, Vector{UInt8}(data); fin)
Base.write(s::Stream, str::AbstractString; fin::Bool = false) = write(s, Vector{UInt8}(codeunits(str)); fin)

"""
    read(s::Stream) -> (bytes, fin)

The next chunk from the peer. `fin` is true on the last one. Throws on reset.
Returns `(UInt8[], true)` once the stream is closed.
"""
function Base.read(s::Stream)
    (isopen(s.inbox) || isready(s.inbox)) || return (UInt8[], true)
    ev = take!(s.inbox)
    ev[1] == :data && return (ev[2], ev[3])
    ev[1] == :reset && error("stream $(s.id) reset by peer: $(ev[2])")
    (UInt8[], true)
end

"Read until FIN and return everything."
function Base.read(s::Stream, ::Type{Vector{UInt8}})
    out = UInt8[]
    while true
        bytes, fin = read(s)
        append!(out, bytes)
        fin && return out
    end
end

"Read exactly `n` bytes (or fewer if the stream ends first)."
function readn(s::Stream, n::Integer)
    out = UInt8[]
    while length(out) < n
        bytes, fin = read(s)
        append!(out, bytes)
        fin && break
    end
    out
end

close_write(s::Stream) = MsQuic.stream_shutdown(s.handle, MsQuic.STREAM_SHUTDOWN_GRACEFUL)
reset(s::Stream, code::Integer = 0) =
    MsQuic.stream_shutdown(s.handle, MsQuic.STREAM_SHUTDOWN_ABORT_SEND | MsQuic.STREAM_SHUTDOWN_ABORT_RECEIVE, code)
Base.close(s::Stream) = s.open && reset(s)

end # module Quic
