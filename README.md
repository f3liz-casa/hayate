# Hayate

**QUIC and WebTransport for Julia, on msquic. The client end.**

[karutte](https://github.com/f3liz-casa/karutte-wt) is WebTransport over HTTP/3 on the BEAM.
Hayate (疾風, a swift wind) is the same thing from the other side: a Julia program that opens a
WebTransport session to a server, sends and receives streams and datagrams, and does not
need a browser to do it.

> **Status: it works, and it is young.** It talks to karutte-core end to end (CONNECT 200,
> bidirectional echo, datagram echo, 200 KB round trips) on real QUIC. The API may still move.
> There is no `msquic_jll` yet, so it borrows the `libmsquic.dylib` that quicer builds.

## What it looks like

```julia
using Hayate: WebTransport

s = WebTransport.connect("https://localhost:4433/asobi?name=koe"; verify = false)

st = WebTransport.open_stream(s)            # bidirectional; header written for you
write(st, "hello"; fin = true)
println(String(read(st, Vector{UInt8})))    # "hello", if the other end echoes

WebTransport.send_datagram(s, "ping")
d = take!(WebTransport.datagrams(s))        # a Channel of payloads from the server

for incoming in WebTransport.incoming_streams(s)   # streams the server opened (server push)
    bytes, fin = read(incoming)
end

close(s)
```

Streams are `read`/`write`. `read(st)` returns `(bytes, fin)`; `read(st, Vector{UInt8})`
collects until FIN. `close_write(st)` half-closes; `reset(st, code)` aborts.

## Layers

The same split quicer uses, so the two ends rhyme:

| Module | What it is |
|---|---|
| `Hayate.MsQuic` | The raw C API. Loads the library, fetches the function table, installs the two callbacks. Struct layouts as measured byte offsets (`test/off.c`). |
| `Hayate.Quic` | `Connection` and `Stream`. Events from msquic's threads land in Channels; the API blocks on them. |
| `Hayate.H3` | Varints, frames, SETTINGS, the WebTransport stream header and datagram prefix, and a static-table-only QPACK that can say CONNECT and read a status. |
| `Hayate.WebTransport` | `Session`: H3 handshake, Extended CONNECT, streams and datagrams routed by session id. |

The one idea worth knowing: msquic calls back from its own worker threads. Each callback
copies what it needs and `put!`s it on the owner's Channel, then returns. Nothing else
happens on msquic's threads. Julia adopts the foreign thread on entry, so this is allowed.

## What it needs

- Julia 1.10 or newer. Run with `-t 2` or more; the session pump is a task.
- `libmsquic`. By default Hayate looks for the one quicer built inside a karutte checkout
  (`~/repos/karutte-wt-next/core/deps/quicer/c_build/msquic/bin/Release/libmsquic.dylib`).
  Point `HAYATE_LIBMSQUIC` at another. An `msquic_jll` is the obvious next step.

## Tests

```sh
julia -t 2 --project=. test/runtests.jl
```

The live tests start a karutte-core echo server (`KARUTTE_CORE` points at the checkout,
default `~/repos/karutte-wt-next/core`) and talk to it on UDP 14499. They are skipped if the
checkout is missing.

## Not yet

- No server side. karutte is the server.
- No certificate pinning. `verify = false` accepts anything, `verify = true` uses the system
  trust store. Pinning a hash the way browsers do with `serverCertificateHashes` would need a
  `PEER_CERTIFICATE_RECEIVED` handler.
- Receive flow control is msquic's defaults. There is no per-stream `active`-style demand yet.
- Capsules on the session stream (CLOSE, DRAIN) are read and ignored.
- QPACK decodes only what a WebTransport status needs. It is not a general HTTP/3 client.
- Only tested on macOS (arm64) against msquic 2.5.7.

## About

Drafted by Shiro (Claude), an AI assistant working alongside nyanrus. If something here is a
misreading, please say so.
