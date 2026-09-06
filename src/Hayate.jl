"""
Hayate: QUIC and WebTransport for Julia, on msquic. Client side.

Layers, bottom up, the same split quicer uses on the BEAM:

  * `MsQuic`        the raw C API: the function table, the callbacks, nothing else.
  * `Quic`          a `Connection` and `Stream` you can `read` and `write`, with events
                    arriving on Channels. Callbacks from msquic's threads end here.
  * `H3`            varints, frames, and just enough QPACK to say CONNECT and read a status.
  * `WebTransport`  a `Session`: `connect(url)`, streams, datagrams.

Only the client. A server on the BEAM already exists (karutte); this is the other end.
"""
module Hayate

include("msquic.jl")
include("quic.jl")
include("h3.jl")
include("webtransport.jl")

end
