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

# --- libtunnel: the shared core (relay + agent both link it) ---
add_library(tunnel STATIC
    src/splice.c)
target_include_directories(tunnel PUBLIC src)
target_compile_options(tunnel PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(tunnel PUBLIC Threads::Threads)

# --- tests ---
option(TUNNEL_BUILD_TESTS "Build tests" ON)
if(TUNNEL_BUILD_TESTS)
    enable_testing()

    # Bidirectional byte pump: integrity both ways, backpressure, half-close.
    add_executable(splice_test tests/splice_test.c)
    target_link_libraries(splice_test PRIVATE tunnel)
    add_test(NAME splice COMMAND splice_test)
endif()
