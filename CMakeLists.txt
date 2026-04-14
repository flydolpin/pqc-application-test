cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(pqc-benchmark
    VERSION 0.1.0
    LANGUAGES C
)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# Options
option(PQC_ENABLE_QUIC "Enable QUIC/HTTP3 benchmarking support" OFF)
option(PQC_ENABLE_TESTS "Build unit tests" ON)

# Dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(liboqs REQUIRED)

# oqs-provider path (needed at runtime)
set(PQC_OQS_PROVIDER_PATH "" CACHE PATH
    "Path to directory containing oqsprovider.so/oqsprovider.dll")

add_subdirectory(src)
add_subdirectory(tools)

if(PQC_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
