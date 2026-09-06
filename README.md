# Hayate

**QUIC and WebTransport for Julia, on msquic. The client end.**

[karutte](https://github.com/f3liz-casa/karutte-wt) is WebTransport over HTTP/3 on the BEAM.
Hayate (疾風, a swift wind) is the same thing from the other side: a Julia program that opens a
WebTransport session to a server, sends and receives streams and datagrams, and does not
need a browser to do it.

> **Status: it works, and it is young.** It talks to karutte-core end to end (CONNECT 200,
> bidirectional echo, datagram echo, 200 KB round trips) on real QUIC; 48 tests. The API may still move.
> There is no `msquic_jll` yet, so it borrows the `libmsquic.dylib` that quicer builds.

## What it looks like

A stream is an `IO`. Everything you already know how to do with one works.

```julia
using Hayate: WebTransport

WebTransport.connect("https://localhost:4433/asobi?name=koe"; verify = false) do s
    st = WebTransport.openstream(s)          # bidirectional; the header is written for you
    print(st, "hello, "); write(st, "hayate")
    closewrite(st)                           # FIN; we can still read
    println(read(st, String))                # "hello, hayate", if the other end echoes
    readline(st); eof(st)                    # all the usual IO verbs

    WebTransport.senddatagram(s, "ping")
    d = take!(WebTransport.datagrams(s))     # a Channel of payloads from the server

    for incoming in WebTransport.streams(s)  # streams the server opened (server push)
        println(read(incoming, String))
    end
end                                          # the do form closes the session
```

`abort(st, code)` resets a stream. Errors are exceptions: `MsQuic.QuicError` (a call failed,
with its status), `Quic.StreamReset` (the peer reset us, with the code),
`Quic.ConnectError` (the handshake failed, with why) and `WebTransport.RejectedError` (the
server answered the CONNECT with a status other than 200).

## Layers

The same split quicer uses, so the two ends rhyme:

| Module | What it is |
|---|---|
| `Hayate.MsQuic` | The raw C API. Loads the library, fetches the function table, installs the two callbacks. C structs are Julia `struct`s with the same layout; a test checks every `fieldoffset` against numbers measured with clang (`test/off.c`). |
| `Hayate.Quic` | `Connection` and `Stream <: IO`. Events from msquic's threads land in Channels; the IO methods block on them. |
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
