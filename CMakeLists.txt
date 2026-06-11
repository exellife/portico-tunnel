cmake_minimum_required(VERSION 3.16)
project(portico_tunnel C)

# portico-tunnel — a reverse tunnel (relay + agent) for hosting from dynamic IPs.
# Built bottom-up; libtunnel grows one tested primitive at a time (see docs/spec.md).

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()
add_compile_definitions(_GNU_SOURCE)

option(TUNNEL_ASAN "Build with AddressSanitizer" OFF)
if(TUNNEL_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()
option(TUNNEL_TSAN "Build with ThreadSanitizer" OFF)
if(TUNNEL_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=thread)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)   # the tunnel is TLS end to end — OpenSSL is mandatory

# --- libtunnel: the shared core (relay + agent both link it) ---
add_library(tunnel STATIC
    src/splice.c
    src/frame.c
    src/io.c
    src/control.c
    src/tls.c)
target_include_directories(tunnel PUBLIC src)
target_compile_options(tunnel PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(tunnel PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# --- tests ---
option(TUNNEL_BUILD_TESTS "Build tests" ON)
if(TUNNEL_BUILD_TESTS)
    enable_testing()

    # Bidirectional byte pump: integrity both ways, backpressure, half-close.
    add_executable(splice_test tests/splice_test.c)
    target_link_libraries(splice_test PRIVATE tunnel)
    add_test(NAME splice COMMAND splice_test)

    # Wire frame codec: roundtrip, big-endian layout, edge cases, streaming reassembly.
    add_executable(frame_test tests/frame_test.c)
    target_link_libraries(frame_test PRIVATE tunnel)
    add_test(NAME frame COMMAND frame_test)

    # Control channel: HELLO codec + register/accept handshake over a socketpair.
    add_executable(control_test tests/control_test.c)
    target_link_libraries(control_test PRIVATE tunnel)
    add_test(NAME control COMMAND control_test)

    # Control handshake over real mTLS: mint CA+certs, verify + register, with the
    # negative controls (untrusted relay cert / no client cert are both rejected).
    add_executable(control_tls_test tests/control_tls_test.c)
    target_link_libraries(control_tls_test PRIVATE tunnel)
    add_test(NAME control_tls COMMAND control_tls_test)
endif()
