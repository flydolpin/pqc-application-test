set(PQC_SOURCES
    crypto/pqc_crypto_factory.c
    benchmark/pqc_timer.c
    benchmark/pqc_metrics.c
    benchmark/pqc_benchmark.c
    benchmark/pqc_reporter.c
    util/pqc_config.c
)

# Backends
list(APPEND PQC_SOURCES
    crypto/backends/oqs_kem.c
    crypto/backends/oqs_sig.c
    crypto/backends/oqs_provider.c
    crypto/backends/classic.c
)

# TLS layer
list(APPEND PQC_SOURCES
    tls/pqc_tls_client.c
    tls/pqc_tls_server.c
    tls/pqc_tls_handshake.c
)

if(PQC_ENABLE_QUIC)
    add_definitions(-DPQC_HAS_QUIC)
    list(APPEND PQC_SOURCES
        quic/pqc_quic_client.c
        quic/pqc_quic_server.c
    )
endif()

add_library(pqc_framework STATIC ${PQC_SOURCES})

target_include_directories(pqc_framework PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_framework PUBLIC
    OQS::oqs
    OpenSSL::SSL
    OpenSSL::Crypto
    m
)
