"""
The raw msquic API. Loads the shared library, fetches the function table, and installs the
two callbacks (connection, stream) that msquic calls from its own worker threads.

Struct layouts are written as byte offsets, measured on this platform with clang against
msquic.h (see `test/off.c`). If msquic changes its structs this is where it breaks, loudly.
"""
module MsQuic

using Libdl

export API, api, Status, STATUS_SUCCESS, STATUS_PENDING, HQUIC

const HQUIC = Ptr{Cvoid}
const Status = UInt32
const STATUS_SUCCESS = Status(0)
const STATUS_PENDING = Status(0xFFFFFFFE)

# Where libmsquic lives. Until there is an msquic_jll, we borrow the one quicer builds.
const DEFAULT_LIB = expanduser("~/repos/karutte-wt-next/core/deps/quicer/c_build/msquic/bin/Release/libmsquic.dylib")
libpath() = get(ENV, "HAYATE_LIBMSQUIC", DEFAULT_LIB)

# Function table, QUIC_API_TABLE, in declaration order (1-based).
const TABLE = (
    SetContext = 1, GetContext = 2, SetCallbackHandler = 3, SetParam = 4, GetParam = 5,
    RegistrationOpen = 6, RegistrationClose = 7, RegistrationShutdown = 8,
    ConfigurationOpen = 9, ConfigurationClose = 10, ConfigurationLoadCredential = 11,
    ListenerOpen = 12, ListenerClose = 13, ListenerStart = 14, ListenerStop = 15,
    ConnectionOpen = 16, ConnectionClose = 17, ConnectionShutdown = 18, ConnectionStart = 19,
    ConnectionSetConfiguration = 20, ConnectionSendResumptionTicket = 21,
    StreamOpen = 22, StreamClose = 23, StreamStart = 24, StreamShutdown = 25, StreamSend = 26,
    StreamReceiveComplete = 27, StreamReceiveSetEnabled = 28, DatagramSend = 29,
)

mutable struct Api
    lib::Ptr{Cvoid}
    table::Ptr{Ptr{Cvoid}}
    registration::HQUIC
end

const API = Ref{Union{Nothing,Api}}(nothing)

"Open msquic once (version 2 table) and one registration for the whole process."
function api()
    a = API[]
    a === nothing || return a
    lib = dlopen(libpath())
    open = dlsym(lib, :MsQuicOpenVersion)
    tbl = Ref{Ptr{Ptr{Cvoid}}}(C_NULL)
    st = ccall(open, Status, (UInt32, Ref{Ptr{Ptr{Cvoid}}}), 2, tbl)
    st == STATUS_SUCCESS || error("MsQuicOpenVersion: 0x$(string(st, base=16))")
    a = Api(lib, tbl[], C_NULL)
    # QUIC_REGISTRATION_CONFIG { const char* AppName; int ExecutionProfile; } (16 bytes)
    cfg = zeros(UInt8, 16)
    name = "hayate"
    GC.@preserve name cfg begin
        unsafe_store!(Ptr{Ptr{UInt8}}(pointer(cfg)), pointer(name))
        reg = Ref{HQUIC}(C_NULL)
        st = ccall(fn(a, :RegistrationOpen), Status, (Ptr{UInt8}, Ref{HQUIC}), cfg, reg)
        st == STATUS_SUCCESS || error("RegistrationOpen: 0x$(string(st, base=16))")
        a.registration = reg[]
    end
    API[] = a
    a
end

fn(a::Api, name::Symbol) = unsafe_load(a.table, TABLE[name])

# --- Flags and enums (values from msquic.h) ---

const CRED_FLAG_CLIENT = UInt32(0x1)
const CRED_FLAG_NO_CERTIFICATE_VALIDATION = UInt32(0x4)
const STREAM_OPEN_UNIDIRECTIONAL = UInt32(0x1)
const SEND_FLAG_FIN = UInt32(0x4)
const STREAM_SHUTDOWN_GRACEFUL = UInt32(0x1)
const STREAM_SHUTDOWN_ABORT_SEND = UInt32(0x2)
const STREAM_SHUTDOWN_ABORT_RECEIVE = UInt32(0x4)
const RECEIVE_FLAG_FIN = UInt32(0x2)

# QUIC_CONNECTION_EVENT_TYPE
const CONN_CONNECTED = 0
const CONN_SHUTDOWN_BY_TRANSPORT = 1
const CONN_SHUTDOWN_BY_PEER = 2
const CONN_SHUTDOWN_COMPLETE = 3
const CONN_PEER_STREAM_STARTED = 6
const CONN_DATAGRAM_STATE_CHANGED = 10
const CONN_DATAGRAM_RECEIVED = 11
const CONN_DATAGRAM_SEND_STATE_CHANGED = 12

# QUIC_STREAM_EVENT_TYPE
const STREAM_START_COMPLETE = 0
const STREAM_RECEIVE = 1
const STREAM_SEND_COMPLETE = 2
const STREAM_PEER_SEND_SHUTDOWN = 3
const STREAM_PEER_SEND_ABORTED = 4
const STREAM_PEER_RECEIVE_ABORTED = 5
const STREAM_SHUTDOWN_COMPLETE = 7

# --- Settings (QUIC_SETTINGS, 144 bytes; IsSetFlags bits and field offsets measured) ---

"""
Build a QUIC_SETTINGS blob. Only the fields we need; everything else stays unset so msquic
uses its defaults.
"""
function settings(; peer_bidi = 256, peer_unidi = 256, datagram_receive = true,
                    idle_timeout_ms = 30_000, keep_alive_ms = 0)
    s = zeros(UInt8, 144)
    isset = UInt64(0)
    isset |= UInt64(1) << 2                     # IdleTimeoutMs
    isset |= UInt64(1) << 18                    # PeerBidiStreamCount
    isset |= UInt64(1) << 19                    # PeerUnidiStreamCount
    isset |= UInt64(1) << 27                    # DatagramReceiveEnabled
    keep_alive_ms > 0 && (isset |= UInt64(1) << 16)   # KeepAliveIntervalMs
    p = pointer(s)
    GC.@preserve s begin
        unsafe_store!(Ptr{UInt64}(p), isset)
        unsafe_store!(Ptr{UInt64}(p + 24), UInt64(idle_timeout_ms))
        unsafe_store!(Ptr{UInt32}(p + 88), UInt32(keep_alive_ms))
        unsafe_store!(Ptr{UInt16}(p + 94), UInt16(peer_bidi))
        unsafe_store!(Ptr{UInt16}(p + 96), UInt16(peer_unidi))
        # bitfield byte at 106: SendBuffering:1 Pacing:1 Migration:1 DatagramReceive:1 ...
        datagram_receive && unsafe_store!(Ptr{UInt8}(p + 106), UInt8(1) << 3)
    end
    s
end

"QUIC_CREDENTIAL_CONFIG (56 bytes). Type NONE; client; optionally skip certificate validation."
function credential(; verify::Bool)
    c = zeros(UInt8, 56)
    flags = CRED_FLAG_CLIENT | (verify ? UInt32(0) : CRED_FLAG_NO_CERTIFICATE_VALIDATION)
    GC.@preserve c unsafe_store!(Ptr{UInt32}(pointer(c) + 4), flags)
    c
end

# --- Callbacks ---
#
# msquic calls these from its worker threads. Julia adopts a foreign thread on entry to a
# @cfunction, so allocating and put!-ing into a Channel here is allowed. What is not allowed is
# blocking for long, or touching the event's buffers after returning. So each callback copies
# what it needs and hands it to the owner's Channel. The owner (Quic.Connection / Quic.Stream)
# is the Context pointer; it is kept rooted in `LIVE` so the pointer stays valid.

const LIVE = IdDict{Any,Nothing}()
const LIVE_LOCK = ReentrantLock()
root!(x) = (lock(LIVE_LOCK) do; LIVE[x] = nothing; end; x)
unroot!(x) = lock(LIVE_LOCK) do; delete!(LIVE, x); end

# Installed by Quic in __init__: (HQUIC, Ptr{Cvoid} ctx, Ptr{Cvoid} event) -> Status
const CONNECTION_CB = Ref{Ptr{Cvoid}}(C_NULL)
const STREAM_CB = Ref{Ptr{Cvoid}}(C_NULL)

# --- Thin wrappers over the table ---

function check(st::Status, what)
    st == STATUS_SUCCESS || st == STATUS_PENDING || error("$what failed: 0x$(string(st, base=16))")
    st
end

function configuration_open(alpn::String, settings::Vector{UInt8})
    a = api()
    buf = zeros(UInt8, 16)    # QUIC_BUFFER {uint32 Length; uint8* Buffer}
    out = Ref{HQUIC}(C_NULL)
    GC.@preserve alpn buf settings begin
        unsafe_store!(Ptr{UInt32}(pointer(buf)), UInt32(sizeof(alpn)))
        unsafe_store!(Ptr{Ptr{UInt8}}(pointer(buf) + 8), pointer(alpn))
        check(ccall(fn(a, :ConfigurationOpen), Status,
                    (HQUIC, Ptr{UInt8}, UInt32, Ptr{UInt8}, UInt32, Ptr{Cvoid}, Ref{HQUIC}),
                    a.registration, buf, 1, settings, length(settings), C_NULL, out), "ConfigurationOpen")
    end
    out[]
end

function configuration_load_credential(cfg::HQUIC, cred::Vector{UInt8})
    GC.@preserve cred check(ccall(fn(api(), :ConfigurationLoadCredential), Status, (HQUIC, Ptr{UInt8}), cfg, cred),
                            "ConfigurationLoadCredential")
end
configuration_close(cfg::HQUIC) = ccall(fn(api(), :ConfigurationClose), Cvoid, (HQUIC,), cfg)

function connection_open(ctx::Ptr{Cvoid})
    out = Ref{HQUIC}(C_NULL)
    check(ccall(fn(api(), :ConnectionOpen), Status, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}, Ref{HQUIC}),
                api().registration, CONNECTION_CB[], ctx, out), "ConnectionOpen")
    out[]
end
function connection_start(conn::HQUIC, cfg::HQUIC, host::String, port::Integer)
    check(ccall(fn(api(), :ConnectionStart), Status, (HQUIC, HQUIC, UInt16, Cstring, UInt16),
                conn, cfg, 0, host, port), "ConnectionStart")
end
connection_shutdown(conn::HQUIC, code::Integer = 0) =
    ccall(fn(api(), :ConnectionShutdown), Cvoid, (HQUIC, UInt32, UInt64), conn, 0, code)
connection_close(conn::HQUIC) = ccall(fn(api(), :ConnectionClose), Cvoid, (HQUIC,), conn)

function stream_open(conn::HQUIC, flags::UInt32, ctx::Ptr{Cvoid})
    out = Ref{HQUIC}(C_NULL)
    check(ccall(fn(api(), :StreamOpen), Status, (HQUIC, UInt32, Ptr{Cvoid}, Ptr{Cvoid}, Ref{HQUIC}),
                conn, flags, STREAM_CB[], ctx, out), "StreamOpen")
    out[]
end
stream_start(s::HQUIC) = check(ccall(fn(api(), :StreamStart), Status, (HQUIC, UInt32), s, 0), "StreamStart")
set_callback_handler(h::HQUIC, cb::Ptr{Cvoid}, ctx::Ptr{Cvoid}) =
    ccall(fn(api(), :SetCallbackHandler), Cvoid, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}), h, cb, ctx)
stream_shutdown(s::HQUIC, flags::UInt32, code::Integer = 0) =
    check(ccall(fn(api(), :StreamShutdown), Status, (HQUIC, UInt32, UInt64), s, flags, code), "StreamShutdown")
stream_close(s::HQUIC) = ccall(fn(api(), :StreamClose), Cvoid, (HQUIC,), s)

"""
A send in flight. msquic reads the bytes asynchronously, so `data` and the QUIC_BUFFER that
points at it must stay alive until SEND_COMPLETE, which hands `ctx` back so we can unroot.
"""
mutable struct Send
    data::Vector{UInt8}
    qbuf::Vector{UInt8}
end
function make_send(data::Vector{UInt8})
    qbuf = zeros(UInt8, 16)
    s = Send(data, qbuf)
    GC.@preserve data qbuf begin
        unsafe_store!(Ptr{UInt32}(pointer(qbuf)), UInt32(length(data)))
        unsafe_store!(Ptr{Ptr{UInt8}}(pointer(qbuf) + 8), pointer(data))
    end
    root!(s)
end

function stream_send(s::HQUIC, data::Vector{UInt8}; fin::Bool = false)
    snd = make_send(data)
    flags = fin ? SEND_FLAG_FIN : UInt32(0)
    st = ccall(fn(api(), :StreamSend), Status, (HQUIC, Ptr{UInt8}, UInt32, UInt32, Ptr{Cvoid}),
               s, snd.qbuf, 1, flags, pointer_from_objref(snd))
    st == STATUS_SUCCESS || st == STATUS_PENDING || (unroot!(snd); error("StreamSend failed: 0x$(string(st, base=16))"))
    nothing
end

function datagram_send(conn::HQUIC, data::Vector{UInt8})
    snd = make_send(data)
    st = ccall(fn(api(), :DatagramSend), Status, (HQUIC, Ptr{UInt8}, UInt32, UInt32, Ptr{Cvoid}),
               conn, snd.qbuf, 1, 0, pointer_from_objref(snd))
    st == STATUS_SUCCESS || st == STATUS_PENDING || (unroot!(snd); error("DatagramSend failed: 0x$(string(st, base=16))"))
    nothing
end

# Read the bytes of a QUIC_BUFFER array (Buffers, count) into one Vector.
function copy_buffers(buffers::Ptr{UInt8}, count::Integer)
    out = UInt8[]
    for i in 0:count-1
        b = buffers + 16i
        len = unsafe_load(Ptr{UInt32}(b))
        ptr = unsafe_load(Ptr{Ptr{UInt8}}(b + 8))
        len == 0 && continue
        append!(out, unsafe_wrap(Vector{UInt8}, ptr, Int(len); own = false))
    end
    out
end

end # module MsQuic
