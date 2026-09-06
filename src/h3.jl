"""
Just enough HTTP/3 for WebTransport: varints (RFC 9000 §16), frames (RFC 9114), the three
unidirectional stream types, SETTINGS, and a QPACK (RFC 9204) encoder and decoder that use
only the static table. That is all a CONNECT and its status need.
"""
module H3

# --- varint ---

function encode_varint(v::Integer)
    v < 0 && throw(ArgumentError("negative varint"))
    v <= 63 && return UInt8[v]
    v <= 16383 && return UInt8[0x40 | (v >> 8), v & 0xff]
    v <= 1073741823 && return UInt8[0x80 | (v >> 24), (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]
    UInt8[0xc0 | (v >> 56), (v >> 48) & 0xff, (v >> 40) & 0xff, (v >> 32) & 0xff, (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]
end

"Decode one varint at `i`. Returns `(value, next_index)` or `nothing` if bytes are short."
function decode_varint(b::AbstractVector{UInt8}, i::Int = 1)
    i <= length(b) || return nothing
    first = b[i]
    n = 1 << (first >> 6)
    i + n - 1 <= length(b) || return nothing
    v = UInt64(first & 0x3f)
    for k in 1:n-1
        v = (v << 8) | b[i+k]
    end
    (Int(v), i + n)
end

# --- frames ---

const FRAME_DATA = 0x00
const FRAME_HEADERS = 0x01
const FRAME_SETTINGS = 0x04
const FRAME_WT_BIDI = 0x41           # WebTransport bidi stream header (frame type on a bidi stream)
const STREAM_CONTROL = 0x00
const STREAM_QPACK_ENCODER = 0x02
const STREAM_QPACK_DECODER = 0x03
const STREAM_WT_UNI = 0x54           # WebTransport uni stream type

frame(type, payload::AbstractVector{UInt8}) = vcat(encode_varint(type), encode_varint(length(payload)), payload)

"Parse one frame at the head. Returns `(type, payload, rest)` or `nothing` if incomplete."
function parse_frame(b::AbstractVector{UInt8})
    r = decode_varint(b); r === nothing && return nothing
    type, i = r
    r = decode_varint(b, i); r === nothing && return nothing
    len, i = r
    i + len - 1 <= length(b) || return nothing
    (type, b[i:i+len-1], b[i+len:end])
end

"SETTINGS for a WebTransport client: ENABLE_CONNECT_PROTOCOL (0x08) and H3_DATAGRAM (0x33)."
client_settings() = frame(FRAME_SETTINGS, vcat(encode_varint(0x08), encode_varint(1), encode_varint(0x33), encode_varint(1)))

"The header that opens a WebTransport stream: type/frame varint, then the session id."
wt_stream_header(session_id, bidi::Bool) = vcat(encode_varint(bidi ? FRAME_WT_BIDI : STREAM_WT_UNI), encode_varint(session_id))

"An HTTP/3 datagram: quarter stream id, then payload."
datagram(session_id, payload::AbstractVector{UInt8}) = vcat(encode_varint(session_id ÷ 4), payload)
function parse_datagram(b::AbstractVector{UInt8})
    r = decode_varint(b); r === nothing && return nothing
    q, i = r
    (q * 4, b[i:end])
end

# --- QPACK, static table only ---

# Static table entries we use (RFC 9204 Appendix A). index => (name, value)
const STATIC = Dict(
    0 => (":authority", ""), 1 => (":path", "/"), 15 => (":method", "CONNECT"), 23 => (":scheme", "https"),
    24 => (":status", "103"), 25 => (":status", "200"), 26 => (":status", "304"), 27 => (":status", "404"),
    28 => (":status", "503"), 63 => (":status", "100"), 64 => (":status", "204"), 65 => (":status", "206"),
    66 => (":status", "302"), 67 => (":status", "400"), 68 => (":status", "403"), 69 => (":status", "421"),
    70 => (":status", "425"), 71 => (":status", "500"),
)

# integer with an N-bit prefix (RFC 7541 §5.1)
function encode_int(v::Integer, prefix::Int, top::UInt8 = 0x00)
    limit = (1 << prefix) - 1
    v < limit && return UInt8[top | v]
    out = UInt8[top | limit]
    v -= limit
    while v >= 128
        push!(out, UInt8(v & 0x7f) | 0x80); v >>= 7
    end
    push!(out, UInt8(v))
    out
end
function decode_int(b::AbstractVector{UInt8}, i::Int, prefix::Int)
    limit = (1 << prefix) - 1
    v = Int(b[i] & limit); i += 1
    v < limit && return (v, i)
    m = 0
    while true
        c = b[i]; i += 1
        v += Int(c & 0x7f) << m; m += 7
        c & 0x80 == 0 && return (v, i)
    end
end

# Literal strings are sent raw (H bit 0). No Huffman on the way out.
encode_string(s::AbstractString) = vcat(encode_int(sizeof(s), 7), Vector{UInt8}(codeunits(s)))

"""
Encode the CONNECT request for a WebTransport session. Indexed static entries for
:method and :scheme; literals with a static name reference for :authority and :path; a literal
name for :protocol (not in the static table).
"""
function encode_connect(authority::AbstractString, path::AbstractString)
    out = UInt8[0x00, 0x00]                                   # prefix: Required Insert Count 0, Base 0
    append!(out, encode_int(15, 6, 0xc0))                     # :method CONNECT (indexed, static)
    append!(out, encode_int(23, 6, 0xc0))                     # :scheme https
    append!(out, encode_int(0, 4, 0x50)); append!(out, encode_string(authority))   # :authority, literal value
    append!(out, encode_int(1, 4, 0x50)); append!(out, encode_string(path))        # :path, literal value
    append!(out, encode_int(9, 3, 0x20)); append!(out, codeunits(":protocol"))     # literal name, H=0
    append!(out, encode_string("webtransport"))
    out
end

# Huffman for the digits only (RFC 7541 Appendix B), enough to read a status the static table lacks.
const HUFF_DIGITS = Dict((0b00000, 5) => '0', (0b00001, 5) => '1', (0b00010, 5) => '2', (0b011001, 6) => '3',
                         (0b011010, 6) => '4', (0b011011, 6) => '5', (0b011100, 6) => '6', (0b011101, 6) => '7',
                         (0b011110, 6) => '8', (0b011111, 6) => '9')
function huffman_digits(b::AbstractVector{UInt8})
    bits = join(string(x, base = 2, pad = 8) for x in b)
    out = Char[]; i = 1
    while i + 4 <= length(bits)
        hit = false
        for n in (5, 6)
            i + n - 1 <= length(bits) || continue
            code = parse(Int, bits[i:i+n-1], base = 2)
            if haskey(HUFF_DIGITS, (code, n))
                push!(out, HUFF_DIGITS[(code, n)]); i += n; hit = true; break
            end
        end
        hit || break                                          # padding, or a non-digit we do not decode
    end
    String(out)
end

function decode_string(b::AbstractVector{UInt8}, i::Int, prefix::Int)
    huff = b[i] & (UInt8(1) << prefix) != 0
    len, i = decode_int(b, i, prefix)
    raw = b[i:i+len-1]
    (huff ? huffman_digits(raw) : String(copy(raw)), i + len)
end

"""
Decode a response field section far enough to find `:status`. Handles indexed static entries,
literals with a static name reference, and literals with a literal name.
"""
function decode_status(block::AbstractVector{UInt8})
    i = 3                                                     # skip the 2-byte prefix (no dynamic table)
    while i <= length(block)
        c = block[i]
        if c & 0x80 != 0                                      # indexed: 1 T idx(6+)
            idx, i = decode_int(block, i, 6)
            e = get(STATIC, idx, nothing)
            e !== nothing && e[1] == ":status" && return e[2]
        elseif c & 0x40 != 0                                  # literal with name ref: 01 N T idx(4+), value
            idx, i = decode_int(block, i, 4)
            val, i = decode_string(block, i, 7)
            e = get(STATIC, idx, nothing)
            e !== nothing && e[1] == ":status" && return val
        elseif c & 0x20 != 0                                  # literal name: 001 N H len(3+), name, value
            name, i = decode_string(block, i, 3)
            val, i = decode_string(block, i, 7)
            name == ":status" && return val
        else
            return nothing                                    # post-base forms need a dynamic table we never allow
        end
    end
    nothing
end

end # module H3
