# Note that this script can accept some limited command-line arguments, run
# `julia build_tarballs.jl --help` to see a usage message.
using BinaryBuilder, Pkg

name = "msquic"
version = v"2.5.7"

# msquic carries its TLS library (quictls, an OpenSSL fork with the QUIC API) as a git
# submodule, which GitSource does not fetch. So quictls is a second source, moved into the
# submodule's path before configuring. Both commits are what msquic v2.5.7 pins.
sources = [
    GitSource("https://github.com/microsoft/msquic.git", "801b0e958f3e33e9998766c3371c1ca348254650"),
    GitSource("https://github.com/quictls/openssl.git", "ff36838bb69801cad56823159a036977bcbe5c75"),
]

script = raw"""
cd ${WORKSPACE}/srcdir
rm -rf msquic/submodules/quictls
mv openssl msquic/submodules/quictls
cd msquic

# C11 static_assert is a macro from <assert.h> that older glibc does not have; msquic's
# posix platform header uses it in C. _Static_assert is the keyword and works everywhere.
export CFLAGS="${CFLAGS} -Dstatic_assert=_Static_assert"

cmake -B build -G Ninja \
    -DCMAKE_INSTALL_PREFIX=${prefix} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TARGET_TOOLCHAIN} \
    -DCMAKE_BUILD_TYPE=Release \
    -DQUIC_TLS_LIB=quictls \
    -DQUIC_BUILD_SHARED=ON \
    -DQUIC_BUILD_TOOLS=OFF \
    -DQUIC_BUILD_TEST=OFF \
    -DQUIC_BUILD_PERF=OFF \
    -DQUIC_ENABLE_LOGGING=OFF \
    -DQUIC_USE_SYSTEM_LIBCRYPTO=OFF
cmake --build build --parallel ${nproc}
cmake --install build
install_license LICENSE
"""

# msquic's posix datapath is epoll (Linux) or kqueue (macOS, FreeBSD). No Windows here yet:
# it would want schannel or a different quictls configure path.
platforms = [
    Platform("x86_64", "linux"; libc="glibc"),
    Platform("aarch64", "linux"; libc="glibc"),
    Platform("x86_64", "linux"; libc="musl"),
    Platform("aarch64", "linux"; libc="musl"),
    Platform("x86_64", "macos"),
    Platform("aarch64", "macos"),
    Platform("x86_64", "freebsd"),
    Platform("aarch64", "freebsd"),
]

products = [
    LibraryProduct("libmsquic", :libmsquic),
]

dependencies = Dependency[]

# quictls's Configure is perl; msquic wants a C11 compiler and cmake ≥ 3.16.
build_tarballs(ARGS, name, version, sources, script, platforms, products, dependencies;
               julia_compat="1.6", preferred_gcc_version=v"9")
