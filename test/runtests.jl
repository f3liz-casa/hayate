using Test
using Hayate
using Hayate: MsQuic, H3, Quic, WebTransport

@testset "msquic: struct layouts match clang (test/off.c)" begin
    @test sizeof(MsQuic.Buffer) == 16
    @test sizeof(MsQuic.RegistrationConfig) == 16
    @test sizeof(MsQuic.CredentialConfig) == 56
    @test fieldoffset(MsQuic.CredentialConfig, 7) == 40      # AllowedCipherSuites
    @test fieldoffset(MsQuic.CredentialConfig, 8) == 48      # CaCertificateFile
    @test sizeof(MsQuic.Settings) == 144
    off(T, name) = fieldoffset(T, findfirst(==(name), fieldnames(T)))
    @test off(MsQuic.Settings, :IdleTimeoutMs) == 24
    @test off(MsQuic.Settings, :KeepAliveIntervalMs) == 88
    @test off(MsQuic.Settings, :PeerBidiStreamCount) == 94
    @test off(MsQuic.Settings, :PeerUnidiStreamCount) == 96
    @test off(MsQuic.Settings, :Bits) == 106
    @test off(MsQuic.Settings, :MaxOperationsPerDrain) == 107
    # event payloads sit at +8; these are offsets within the payload
    @test off(MsQuic.EvShutdownByTransport, :ErrorCode) == 8   # 16 - 8
    @test off(MsQuic.EvPeerStreamStarted, :Flags) == 8         # 16 - 8
    @test off(MsQuic.EvDatagramStateChanged, :MaxSendLength) == 2
    @test off(MsQuic.EvStartComplete, :ID) == 8
    @test off(MsQuic.EvReceive, :Buffers) == 16 && off(MsQuic.EvReceive, :BufferCount) == 24 && off(MsQuic.EvReceive, :Flags) == 28
    @test off(MsQuic.EvSendComplete, :ClientContext) == 8
end

@testset "h3: varint" begin
    for v in (0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903)
        b = H3.encode_varint(v)
        @test H3.decode_varint(b) == (v, length(b) + 1)
    end
    @test H3.decode_varint(UInt8[0x40]) === nothing
    @test H3.encode_varint(0x41) == UInt8[0x40, 0x41]
end

@testset "h3: wire bytes match cowlib" begin
    # printed from cowlib in karutte-core, so the two ends agree byte for byte
    @test H3.wt_stream_header(0, true) == UInt8[0x40, 0x41, 0x00]
    @test H3.wt_stream_header(4, false) == UInt8[0x40, 0x54, 0x04]
    @test H3.datagram(4, Vector{UInt8}("hi")) == UInt8[0x01, 0x68, 0x69]
    @test H3.parse_datagram(UInt8[0x01, 0x68, 0x69]) == (4, Vector{UInt8}("hi"))
    @test H3.client_settings() == UInt8[0x04, 0x04, 0x08, 0x01, 0x33, 0x01]
    @test H3.parse_frame(UInt8[0x01, 0x03, 0xc0, 0xd9, 0xee]) == (1, UInt8[0xc0, 0xd9, 0xee], UInt8[])
end

@testset "h3: qpack static-only" begin
    blk = H3.encode_connect("localhost", "/asobi?name=x")
    @test blk[1:4] == UInt8[0x00, 0x00, 0xcf, 0xd7]            # prefix, :method CONNECT, :scheme https
    @test H3.decode_status(UInt8[0x00, 0x00, 0xd9]) == "200"   # what cowlib sends for 200
    @test H3.decode_status(UInt8[0x00, 0x00, 0xff, 0x05]) == "403"
    # Huffman digits (RFC 7541 codes): '4' = 011010, '0' = 00000, '1' = 00001, then 1-padding
    @test H3.huffman_digits(UInt8[0b011010_00, 0b000_00001, 0b11111111]) == "401"
end

# --- Against a real karutte-core echo server, if one is reachable ---

const CORE = get(ENV, "KARUTTE_CORE", expanduser("~/repos/karutte-wt-next/core"))
const PORT = 14_499

function with_server(f)
    isdir(CORE) || (@warn "karutte-core not found at $CORE; skipping live tests"; return)
    boot = """
    {:ok, c} = Karutte.Http3.Cert.generate(Path.join(System.tmp_dir!(), "hayate_cert"))
    {:ok, _} = Karutte.Http3.Server.start_link(port: $PORT, certfile: c.certfile, keyfile: c.keyfile, handler: Karutte.Http3.Echo)
    Process.sleep(:infinity)
    """
    p = run(pipeline(Cmd(`mix run --no-halt -e $boot`; dir = CORE); stdout = devnull, stderr = devnull); wait = false)
    try
        sleep(4)
        f()
    finally
        kill(p); wait(p)
    end
end

with_server() do
    @testset "webtransport: streams are IO, datagrams are a Channel" begin
        WebTransport.connect("https://localhost:$PORT/"; verify = false) do s
            @test s.id >= 0
            @test isopen(s)

            st = WebTransport.openstream(s)
            print(st, "hello, "); write(st, "hayate"); closewrite(st)
            @test read(st, String) == "hello, hayate"
            @test eof(st)

            st2 = WebTransport.openstream(s)
            write(st2, "line one\nline two\n"); closewrite(st2)
            @test readline(st2) == "line one"
            @test readline(st2) == "line two"

            WebTransport.senddatagram(s, "ping")
            d = Quic.take_within(WebTransport.datagrams(s), 3.0)
            @test d !== nothing && String(d) == "ping"

            big = rand(UInt8, 200_000)
            st3 = WebTransport.openstream(s)
            write(st3, big); closewrite(st3)
            @test read(st3) == big
        end
    end

    @testset "errors are exceptions with a story" begin
        @test_throws Quic.ConnectError WebTransport.connect("https://localhost:1/"; verify = false, timeout = 1.0)
        @test_throws ArgumentError WebTransport.connect("http://nope")
    end
end
