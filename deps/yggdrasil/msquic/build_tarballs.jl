# Note that this script can accept some limited command-line arguments, run
# `julia build_tarballs.jl --help` to see a usage message.
using BinaryBuilder, Pkg

name = "msquic"
version = v"2.5.7"

# msquic carries its TLS library (quictls, an OpenSSL fork with the QUIC API) as a git
# submodule, which GitSource does not fetch, and its submodule CMake configures quictls with
# host auto-detection (`config`, or `xcrun` on macOS), which points the wrong way under
# cross-compilation. So quictls is a second source, built here with an explicit target per
# platform, and msquic's submodule CMake is replaced by a stub that points at the result.
# Both commits are what msquic v2.5.7 pins.
sources = [
    GitSource("https://github.com/microsoft/msquic.git", "801b0e958f3e33e9998766c3371c1ca348254650"),
    GitSource("https://github.com/quictls/openssl.git", "ff36838bb69801cad56823159a036977bcbe5c75"),
    # msquic's macOS certificate code calls SecTrustEvaluateWithError (macOS 10.14). The
    # default x86_64 SDK is older, so bring the 10.14 one, the way other Yggdrasil recipes do.
    ArchiveSource("https://github.com/phracker/MacOSX-SDKs/releases/download/10.15/MacOSX10.14.sdk.tar.xz",
                  "0f03869f72df8705b832910517b47dd5b79eb4e160512602f593ed243b28715f"),
]

script = raw"""
cd ${WORKSPACE}/srcdir

if [[ "${target}" == x86_64-apple-darwin* ]]; then
    # A newer macOS SDK, for SecTrustEvaluateWithError.
    pushd ${WORKSPACE}/srcdir/MacOSX10.14.sdk
    rm -rf /opt/${target}/${target}/sys-root/System
    cp -ra usr/* "/opt/${target}/${target}/sys-root/usr/."
    cp -ra System "/opt/${target}/${target}/sys-root/."
    popd
    export MACOSX_DEPLOYMENT_TARGET=10.14
fi

# --- 1. quictls, static, configured for the target by name ---
case "${target}" in
    x86_64-linux-*)      ssl_target=linux-x86_64 ;;
    i686-linux-*)        ssl_target=linux-x86 ;;
    aarch64-linux-*)     ssl_target=linux-aarch64 ;;
    arm*-linux-*)        ssl_target=linux-armv4 ;;
    powerpc64le-linux-*) ssl_target=linux-ppc64le ;;
    riscv64-linux-*)     ssl_target=linux64-riscv64 ;;
    x86_64-apple-*)      ssl_target=darwin64-x86_64-cc ;;
    aarch64-apple-*)     ssl_target=darwin64-arm64-cc ;;
    x86_64-*-freebsd*)   ssl_target=BSD-x86_64 ;;
    aarch64-*-freebsd*)  ssl_target=BSD-aarch64 ;;
    x86_64-w64-mingw32)  ssl_target=mingw64 ;;
    i686-w64-mingw32)    ssl_target=mingw ;;
    *) echo "no quictls target for ${target}"; exit 1 ;;
esac

# The same feature set msquic's own build asks for (submodules/CMakeLists.txt), minus the
# sanitizer bits. TLS 1.3 only; nothing shared; no tests.
ssl_flags="enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp no-zlib no-egd no-idea
    no-rc5 no-rc4 no-afalgeng no-comp no-cms no-ct no-srtp no-ts no-gost no-dso no-ec2m
    no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-ssl no-ssl3-method
    no-tls1-method no-tls1_1-method no-tls1_2-method no-dtls1-method no-dtls1_2-method
    no-siphash no-whirlpool no-aria no-bf no-blake2 no-sm2 no-sm3 no-sm4 no-camellia no-cast
    no-md4 no-mdc2 no-ocb no-rc2 no-rmd160 no-scrypt no-seed no-weak-ssl-ciphers no-shared
    no-tests no-uplink no-cmp no-fips no-padlockeng no-siv no-legacy no-deprecated"

QUICTLS=${WORKSPACE}/quictls
cd openssl
perl ./Configure ${ssl_target} --prefix=${QUICTLS} --libdir=lib ${ssl_flags}
make -j${nproc} build_libs
# Not `make install_dev`: OpenSSL's darwin targets run `ranlib -c`, which llvm-ranlib rejects.
# The two archives and the headers are all msquic needs.
mkdir -p ${QUICTLS}/lib ${QUICTLS}/include
cp libssl.a libcrypto.a ${QUICTLS}/lib/
cp -r include/openssl ${QUICTLS}/include/
cd ..

# --- 2. msquic, told that quictls is already there ---
cat > msquic/submodules/CMakeLists.txt <<CMAKE
cmake_minimum_required(VERSION 3.16)
project(OpenSSLQuic)
add_library(OpenSSLQuic INTERFACE)
target_include_directories(OpenSSLQuic INTERFACE ${QUICTLS}/include)
target_link_libraries(OpenSSLQuic INTERFACE ${QUICTLS}/lib/libssl.a ${QUICTLS}/lib/libcrypto.a)
add_library(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic)
CMAKE

cd msquic
# C11 static_assert is a macro from <assert.h> that older glibc does not have; msquic's
# posix platform header uses it in C. _Static_assert is the keyword and works everywhere.
export CFLAGS="${CFLAGS} -Dstatic_assert=_Static_assert"
extra=""
case "${target}" in
    arm*-linux-*|aarch64-linux-*|riscv64-linux-*) extra="-DCMAKE_EXE_LINKER_FLAGS=-latomic -DCMAKE_SHARED_LINKER_FLAGS=-latomic" ;;
esac

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
    -DQUIC_USE_SYSTEM_LIBCRYPTO=OFF \
    ${extra}
cmake --build build --parallel ${nproc}
cmake --install build
install_license LICENSE
"""

# msquic's posix datapath is epoll on Linux and kqueue on macOS. It has no FreeBSD platform
# of its own (kqueue plus the Linux headers collide), and its Windows platform is written for
# MSVC, which mingw is not. So: Linux and macOS, every architecture.
platforms = filter(supported_platforms()) do p
    Sys.islinux(p) || Sys.isapple(p)
end

products = [
    LibraryProduct("libmsquic", :libmsquic),
]

dependencies = Dependency[]

# quictls's Configure is perl; msquic wants a C11 compiler and cmake ≥ 3.16.
build_tarballs(ARGS, name, version, sources, script, platforms, products, dependencies;
               julia_compat="1.6", preferred_gcc_version=v"9")
