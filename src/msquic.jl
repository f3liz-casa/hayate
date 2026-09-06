"""
The raw msquic API. Loads the shared library, fetches the function table, and installs the
two callbacks (connection, stream) that msquic calls from its own worker threads.

C structs are declared as Julia `struct`s with the same layout, so fields are read by name.
`test/runtests.jl` checks `sizeof` and `fieldoffset` against numbers measured with clang
(`test/off.c`). If msquic changes a struct, that test is where it breaks, loudly.
"""
module MsQuic

using Libdl

const HQUIC = Ptr{Cvoid}
const Status = UInt32
const STATUS_SUCCESS = Status(0)
const STATUS_PENDING = Status(0xFFFFFFFE)

struct QuicError <: Exception
    call::Symbol
    status::Status
end
Base.showerror(io::IO, e::QuicError) = print(io, "msquic ", e.call, " failed: 0x", string(e.status, base = 16))

# Where libmsquic lives. Until there is an msquic_jll, we borrow the one quicer builds.
const DEFAULT_LIB = expanduser("~/repos/karutte-wt-next/core/deps/quicer/c_build/msquic/bin/Release/libmsquic.dylib")
libpath() = get(ENV, "HAYATE_LIBMSQUIC", DEFAULT_LIB)

# --- C structs, laid out as in msquic.h ---

struct Buffer                      # QUIC_BUFFER
    Length::UInt32
    Buffer::Ptr{UInt8}
end

struct RegistrationConfig          # QUIC_REGISTRATION_CONFIG
    AppName::Cstring
    ExecutionProfile::Int32
end

struct CredentialConfig            # QUIC_CREDENTIAL_CONFIG
    Type::Int32
    Flags::UInt32
    Certificate::Ptr{Cvoid}
    Principal::Cstring
    Reserved::Ptr{Cvoid}
    AsyncHandler::Ptr{Cvoid}
    AllowedCipherSuites::UInt32
    CaCertificateFile::Cstring
end

Base.@kwdef struct Settings        # QUIC_SETTINGS (144 bytes)
    IsSetFlags::UInt64 = 0
    MaxBytesPerKey::UInt64 = 0
    HandshakeIdleTimeoutMs::UInt64 = 0
    IdleTimeoutMs::UInt64 = 0
    MtuDiscoverySearchCompleteTimeoutUs::UInt64 = 0
    TlsClientMaxSendBuffer::UInt32 = 0
    TlsServerMaxSendBuffer::UInt32 = 0
    StreamRecvWindowDefault::UInt32 = 0
    StreamRecvBufferDefault::UInt32 = 0
    ConnFlowControlWindow::UInt32 = 0
    MaxWorkerQueueDelayUs::UInt32 = 0
    MaxStatelessOperations::UInt32 = 0
    InitialWindowPackets::UInt32 = 0
    SendIdleTimeoutMs::UInt32 = 0
    InitialRttMs::UInt32 = 0
    MaxAckDelayMs::UInt32 = 0
    DisconnectTimeoutMs::UInt32 = 0
    KeepAliveIntervalMs::UInt32 = 0
    CongestionControlAlgorithm::UInt16 = 0
    PeerBidiStreamCount::UInt16 = 0
    PeerUnidiStreamCount::UInt16 = 0
    MaxBindingStatelessOperations::UInt16 = 0
    StatelessOperationExpirationMs::UInt16 = 0
    MinimumMtu::UInt16 = 0
    MaximumMtu::UInt16 = 0
    Bits::UInt8 = 0                # SendBuffering:1 Pacing:1 Migration:1 DatagramReceive:1 ServerResumptionLevel:2 GreaseQuicBit:1 Ecn:1
    MaxOperationsPerDrain::UInt8 = 0
    MtuDiscoveryMissingProbeCount::UInt8 = 0
    DestCidUpdateIdleTimeoutMs::UInt32 = 0
    Flags::UInt64 = 0
    StreamRecvWindowBidiLocalDefault::UInt32 = 0
    StreamRecvWindowBidiRemoteDefault::UInt32 = 0
    StreamRecvWindowUnidiDefault::UInt32 = 0
end

# IsSetFlags bit positions (order of the IsSet bitfield in msquic.h)
const ISSET_IDLE_TIMEOUT = UInt64(1) << 2
const ISSET_KEEP_ALIVE = UInt64(1) << 16
const ISSET_PEER_BIDI = UInt64(1) << 18
const ISSET_PEER_UNIDI = UInt64(1) << 19
const ISSET_DATAGRAM_RECEIVE = UInt64(1) << 27
const BIT_DATAGRAM_RECEIVE = UInt8(1) << 3

"""
Settings for a client. Fields left unset keep msquic's defaults. The peer stream counts
matter: the server opens three unidirectional streams (control, QPACK encoder, decoder)
before anything else can happen.
"""
function settings(; peer_bidi = 256, peer_unidi = 256, datagram_receive = true,
                    idle_timeout_ms = 30_000, keep_alive_ms = 0)
    isset = ISSET_IDLE_TIMEOUT | ISSET_PEER_BIDI | ISSET_PEER_UNIDI | ISSET_DATAGRAM_RECEIVE |
            (keep_alive_ms > 0 ? ISSET_KEEP_ALIVE : 0)
    Settings(; IsSetFlags = isset, IdleTimeoutMs = idle_timeout_ms, KeepAliveIntervalMs = keep_alive_ms,
               PeerBidiStreamCount = peer_bidi, PeerUnidiStreamCount = peer_unidi,
               Bits = datagram_receive ? BIT_DATAGRAM_RECEIVE : 0x00)
end

# Event payloads. Each sits at offset 8 of the event struct, after the 4-byte type and padding.
struct EvConnected;           SessionResumed::UInt8; NegotiatedAlpnLength::UInt8; NegotiatedAlpn::Ptr{UInt8}; end
struct EvShutdownByTransport; Status::Status; ErrorCode::UInt64; end
struct EvShutdownByPeer;      ErrorCode::UInt64; end
struct EvPeerStreamStarted;   Stream::HQUIC; Flags::UInt32; end
struct EvDatagramStateChanged; SendEnabled::UInt8; MaxSendLength::UInt16; end
struct EvDatagramReceived;    Buffer::Ptr{Buffer}; Flags::UInt32; end
struct EvDatagramSendState;   ClientContext::Ptr{Cvoid}; State::UInt32; end
struct EvStartComplete;       Status::Status; ID::UInt64; PeerAccepted::UInt8; end
struct EvReceive;             AbsoluteOffset::UInt64; TotalBufferLength::UInt64; Buffers::Ptr{Buffer}; BufferCount::UInt32; Flags::UInt32; end
struct EvSendComplete;        Canceled::UInt8; ClientContext::Ptr{Cvoid}; end
struct EvPeerSendAborted;     ErrorCode::UInt64; end

event_type(ev::Ptr{Cvoid}) = unsafe_load(Ptr{UInt32}(ev))
payload(::Type{T}, ev::Ptr{Cvoid}) where {T} = unsafe_load(Ptr{T}(ev + 8))

@enum ConnectionEvent::UInt32 begin
    CONNECTED = 0
    SHUTDOWN_INITIATED_BY_TRANSPORT = 1
    SHUTDOWN_INITIATED_BY_PEER = 2
    SHUTDOWN_COMPLETE = 3
    LOCAL_ADDRESS_CHANGED = 4
    PEER_ADDRESS_CHANGED = 5
    PEER_STREAM_STARTED = 6
    STREAMS_AVAILABLE = 7
    PEER_NEEDS_STREAMS = 8
    IDEAL_PROCESSOR_CHANGED = 9
    DATAGRAM_STATE_CHANGED = 10
    DATAGRAM_RECEIVED = 11
    DATAGRAM_SEND_STATE_CHANGED = 12
    RESUMED = 13
    RESUMPTION_TICKET_RECEIVED = 14
    PEER_CERTIFICATE_RECEIVED = 15
end

@enum StreamEvent::UInt32 begin
    START_COMPLETE = 0
    RECEIVE = 1
    SEND_COMPLETE = 2
    PEER_SEND_SHUTDOWN = 3
    PEER_SEND_ABORTED = 4
    PEER_RECEIVE_ABORTED = 5
    SEND_SHUTDOWN_COMPLETE = 6
    STREAM_SHUTDOWN_COMPLETE = 7
    IDEAL_SEND_BUFFER_SIZE = 8
    PEER_ACCEPTED = 9
    CANCEL_ON_LOSS = 10
end

# QUIC_DATAGRAM_SEND_STATE. A datagram's context comes back once per state change; only the
# terminal ones mean msquic is done with the buffer.
@enum DatagramSendState::UInt32 begin
    DGRAM_UNKNOWN = 0
    DGRAM_SENT = 1
    DGRAM_LOST_SUSPECT = 2
    DGRAM_LOST_DISCARDED = 3
    DGRAM_ACKNOWLEDGED = 4
    DGRAM_ACKNOWLEDGED_SPURIOUS = 5
    DGRAM_CANCELED = 6
end
dgram_terminal(st::UInt32) = st in (UInt32(3), UInt32(4), UInt32(5), UInt32(6))

# Flags
const CRED_FLAG_CLIENT = UInt32(0x1)
const CRED_FLAG_NO_CERTIFICATE_VALIDATION = UInt32(0x4)
const STREAM_OPEN_UNIDIRECTIONAL = UInt32(0x1)
const SEND_FLAG_FIN = UInt32(0x4)
const STREAM_SHUTDOWN_GRACEFUL = UInt32(0x1)
const STREAM_SHUTDOWN_ABORT = UInt32(0x6)
const RECEIVE_FLAG_FIN = UInt32(0x2)

# --- The library and its function table ---

# QUIC_API_TABLE, in declaration order.
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
const API_LOCK = ReentrantLock()

"Open msquic once (version 2 table) and one registration for the whole process."
function api()
    lock(API_LOCK) do
        a = API[]
        a === nothing || return a
        lib = dlopen(libpath())
        tbl = Ref{Ptr{Ptr{Cvoid}}}(C_NULL)
        st = ccall(dlsym(lib, :MsQuicOpenVersion), Status, (UInt32, Ref{Ptr{Ptr{Cvoid}}}), 2, tbl)
        st == STATUS_SUCCESS || throw(QuicError(:MsQuicOpenVersion, st))
        a = Api(lib, tbl[], C_NULL)
        name = "hayate"
        reg = Ref{HQUIC}(C_NULL)
        GC.@preserve name begin
            cfg = Ref(RegistrationConfig(pointer(name), 0))
            check(:RegistrationOpen, ccall(fn(a, :RegistrationOpen), Status, (Ref{RegistrationConfig}, Ref{HQUIC}), cfg, reg))
        end
        a.registration = reg[]
        API[] = a
    end
end

fn(a::Api, name::Symbol) = unsafe_load(a.table, TABLE[name])
fn(name::Symbol) = fn(api(), name)

function check(call::Symbol, st::Status)
    st == STATUS_SUCCESS || st == STATUS_PENDING || throw(QuicError(call, st))
    st
end

# --- Rooting ---
#
# msquic keeps our Context pointers and, for sends, our buffers. Anything it may still touch
# is held here so the GC leaves it alone; it is released when msquic says it is done.

const LIVE = IdDict{Any,Nothing}()
const LIVE_LOCK = ReentrantLock()
root!(x) = (lock(() -> (LIVE[x] = nothing), LIVE_LOCK); x)
unroot!(x) = lock(() -> delete!(LIVE, x), LIVE_LOCK)
unroot!(p::Ptr{Cvoid}) = p == C_NULL || unroot!(unsafe_pointer_to_objref(p))

# Installed by Quic.__init__: (HQUIC, Ptr{Cvoid} ctx, Ptr{Cvoid} event) -> Status
const CONNECTION_CB = Ref{Ptr{Cvoid}}(C_NULL)
const STREAM_CB = Ref{Ptr{Cvoid}}(C_NULL)

# --- Wrappers over the table ---

function configuration_open(alpn::String, s::Settings)
    a = api()
    out = Ref{HQUIC}(C_NULL)
    GC.@preserve alpn begin
        buf = Ref(Buffer(sizeof(alpn), pointer(alpn)))
        check(:ConfigurationOpen, ccall(fn(a, :ConfigurationOpen), Status,
              (HQUIC, Ref{Buffer}, UInt32, Ref{Settings}, UInt32, Ptr{Cvoid}, Ref{HQUIC}),
              a.registration, buf, 1, Ref(s), sizeof(Settings), C_NULL, out))
    end
    out[]
end

function configuration_load_credential(cfg::HQUIC; verify::Bool)
    flags = CRED_FLAG_CLIENT | (verify ? 0x0 : CRED_FLAG_NO_CERTIFICATE_VALIDATION)
    cred = Ref(CredentialConfig(0, flags, C_NULL, C_NULL, C_NULL, C_NULL, 0, C_NULL))
    check(:ConfigurationLoadCredential, ccall(fn(:ConfigurationLoadCredential), Status, (HQUIC, Ref{CredentialConfig}), cfg, cred))
end
configuration_close(cfg::HQUIC) = ccall(fn(:ConfigurationClose), Cvoid, (HQUIC,), cfg)

function connection_open(ctx::Ptr{Cvoid})
    out = Ref{HQUIC}(C_NULL)
    check(:ConnectionOpen, ccall(fn(:ConnectionOpen), Status, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}, Ref{HQUIC}),
                                 api().registration, CONNECTION_CB[], ctx, out))
    out[]
end
connection_start(conn::HQUIC, cfg::HQUIC, host::String, port::Integer) =
    check(:ConnectionStart, ccall(fn(:ConnectionStart), Status, (HQUIC, HQUIC, UInt16, Cstring, UInt16), conn, cfg, 0, host, port))
connection_shutdown(conn::HQUIC, code::Integer = 0) = ccall(fn(:ConnectionShutdown), Cvoid, (HQUIC, UInt32, UInt64), conn, 0, code)
connection_close(conn::HQUIC) = ccall(fn(:ConnectionClose), Cvoid, (HQUIC,), conn)

function stream_open(conn::HQUIC, flags::UInt32, ctx::Ptr{Cvoid})
    out = Ref{HQUIC}(C_NULL)
    check(:StreamOpen, ccall(fn(:StreamOpen), Status, (HQUIC, UInt32, Ptr{Cvoid}, Ptr{Cvoid}, Ref{HQUIC}), conn, flags, STREAM_CB[], ctx, out))
    out[]
end
stream_start(s::HQUIC) = check(:StreamStart, ccall(fn(:StreamStart), Status, (HQUIC, UInt32), s, 0))
set_callback_handler(h::HQUIC, cb::Ptr{Cvoid}, ctx::Ptr{Cvoid}) = ccall(fn(:SetCallbackHandler), Cvoid, (HQUIC, Ptr{Cvoid}, Ptr{Cvoid}), h, cb, ctx)
stream_shutdown(s::HQUIC, flags::UInt32, code::Integer = 0) = check(:StreamShutdown, ccall(fn(:StreamShutdown), Status, (HQUIC, UInt32, UInt64), s, flags, code))
stream_close(s::HQUIC) = ccall(fn(:StreamClose), Cvoid, (HQUIC,), s)

"""
A send in flight. msquic reads `data` asynchronously, so it and the `Buffer` that points at it
stay rooted until SEND_COMPLETE (or the datagram send state) hands the context back.
"""
mutable struct Send
    data::Vector{UInt8}
    buffer::Ref{Buffer}
end
function Send(data::Vector{UInt8})
    s = Send(data, Ref(Buffer(length(data), pointer(data))))
    root!(s)
end

function stream_send(s::HQUIC, data::Vector{UInt8}; fin::Bool = false)
    snd = Send(data)
    st = ccall(fn(:StreamSend), Status, (HQUIC, Ref{Buffer}, UInt32, UInt32, Ptr{Cvoid}),
               s, snd.buffer, 1, fin ? SEND_FLAG_FIN : 0x0, pointer_from_objref(snd))
    st == STATUS_SUCCESS || st == STATUS_PENDING || (unroot!(snd); throw(QuicError(:StreamSend, st)))
    nothing
end

function datagram_send(conn::HQUIC, data::Vector{UInt8})
    snd = Send(data)
    st = ccall(fn(:DatagramSend), Status, (HQUIC, Ref{Buffer}, UInt32, UInt32, Ptr{Cvoid}),
               conn, snd.buffer, 1, 0, pointer_from_objref(snd))
    st == STATUS_SUCCESS || st == STATUS_PENDING || (unroot!(snd); throw(QuicError(:DatagramSend, st)))
    nothing
end

"Copy the bytes of `count` QUIC_BUFFERs into one Vector. Valid only during the callback."
function copy_buffers(buffers::Ptr{Buffer}, count::Integer)
    out = UInt8[]
    for i in 1:count
        b = unsafe_load(buffers, i)
        b.Length == 0 && continue
        append!(out, unsafe_wrap(Vector{UInt8}, b.Buffer, Int(b.Length); own = false))
    end
    out
end

end # module MsQuic
