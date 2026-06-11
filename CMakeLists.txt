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
    src/tls.c
    src/stream.c
    src/sni.c
    src/conn.c)
target_include_directories(tunnel PUBLIC src)
target_compile_options(tunnel PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(tunnel PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# --- the runnable binary ---
add_executable(portico-tunnel src/main.c)
target_compile_options(portico-tunnel PRIVATE -Wall -Wextra)
target_link_libraries(portico-tunnel PRIVATE tunnel)

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

    # Agent stream engine: OPEN -> dial local + bridge, DATA both ways, END/RESET,
    # multiplexing + backpressure, against a real local echo server.
    add_executable(stream_test tests/stream_test.c)
    target_link_libraries(stream_test PRIVATE tunnel)
    add_test(NAME stream COMMAND stream_test)

    # Relay <-> agent end to end: public client -> relay -> tunnel -> agent -> echo.
    add_executable(relay_test tests/relay_test.c)
    target_link_libraries(relay_test PRIVATE tunnel)
    add_test(NAME relay COMMAND relay_test)

    # Full data plane over a real mTLS tunnel (exercises the non-blocking SSL transport).
    add_executable(relay_tls_test tests/relay_tls_test.c)
    target_link_libraries(relay_tls_test PRIVATE tunnel)
    add_test(NAME relay_tls COMMAND relay_tls_test)

    # Agent reconnect: relay drops each session; the run loop must keep redialing.
    add_executable(reconnect_test tests/reconnect_test.c)
    target_link_libraries(reconnect_test PRIVATE tunnel)
    add_test(NAME reconnect COMMAND reconnect_test)

    # H1: relay control handshake/HELLO deadline — a staller cannot freeze the relay.
    add_executable(relay_deadline_test tests/relay_deadline_test.c)
    target_link_libraries(relay_deadline_test PRIVATE tunnel)
    add_test(NAME relay_deadline COMMAND relay_deadline_test)

    # M5: agent registration timeout — a mute relay does not wedge the agent.
    add_executable(register_timeout_test tests/register_timeout_test.c)
    target_link_libraries(register_timeout_test PRIVATE tunnel)
    add_test(NAME register_timeout COMMAND register_timeout_test)

    # H5: non-blocking local connect — a black-holed connect does not freeze the engine.
    add_executable(connect_test tests/connect_test.c)
    target_link_libraries(connect_test PRIVATE tunnel)
    add_test(NAME connect COMMAND connect_test)

    # M1: open_public commits OPEN + buffered ClientHello atomically under tw backpressure.
    add_executable(open_atomic_test tests/open_atomic_test.c)
    target_link_libraries(open_atomic_test PRIVATE tunnel)
    add_test(NAME open_atomic COMMAND open_atomic_test)

    # M10: backoff grows across instantly-dropped (useless) sessions instead of pinning.
    add_executable(backoff_test tests/backoff_test.c)
    target_link_libraries(backoff_test PRIVATE tunnel)
    add_test(NAME backoff COMMAND backoff_test)

    # M9: serve_loop honors the stop flag mid-session (no wedge on a live idle tunnel).
    add_executable(stop_flag_test tests/stop_flag_test.c)
    target_link_libraries(stop_flag_test PRIVATE tunnel)
    add_test(NAME stop_flag COMMAND stop_flag_test)

    # M11: a duplicate OPEN for an active stream_id is rejected (no double-open).
    add_executable(dup_open_test tests/dup_open_test.c)
    target_link_libraries(dup_open_test PRIVATE tunnel)
    add_test(NAME dup_open COMMAND dup_open_test)

    # M6: registration decoder handoff — a frame pipelined after HELLO_OK isn't lost.
    add_executable(register_handoff_test tests/register_handoff_test.c)
    target_link_libraries(register_handoff_test PRIVATE tunnel)
    add_test(NAME register_handoff COMMAND register_handoff_test)

    # M2: teardown frames (END/RESET) survive tw backpressure — never silently dropped.
    add_executable(teardown_test tests/teardown_test.c)
    target_link_libraries(teardown_test PRIVATE tunnel)
    add_test(NAME teardown COMMAND teardown_test)

    # W2: idle reaping — slowloris peekers reaped, tcp decoupled, healthy-idle preserved.
    add_executable(idle_reaping_test tests/idle_reaping_test.c)
    target_link_libraries(idle_reaping_test PRIVATE tunnel)
    add_test(NAME idle_reaping COMMAND idle_reaping_test)

    # CLI integration: run the actual binary (relay + agent) and tunnel a tcp forward.
    add_test(NAME cli COMMAND bash ${CMAKE_SOURCE_DIR}/tests/cli_test.sh $<TARGET_FILE:portico-tunnel>)

    # TLS SNI peek: parse real OpenSSL ClientHellos + hostile inputs.
    add_executable(sni_test tests/sni_test.c)
    target_link_libraries(sni_test PRIVATE tunnel)
    add_test(NAME sni COMMAND sni_test)
endif()
