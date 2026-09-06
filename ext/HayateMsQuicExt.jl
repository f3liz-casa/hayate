"""
Loaded automatically when both Hayate and msquic_jll are in the session. Points Hayate at
the jll's libmsquic, so nothing has to be built or found by hand.
"""
module HayateMsQuicExt

using Hayate, msquic_jll

function __init__()
    Hayate.MsQuic.LIB[] = msquic_jll.libmsquic
end

end
