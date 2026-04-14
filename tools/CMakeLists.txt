add_executable(pqc_bench_tls pqc_bench_tls.c)
target_link_libraries(pqc_bench_tls PRIVATE pqc_framework)

add_executable(pqc_tls_server pqc_tls_server.c)
target_link_libraries(pqc_tls_server PRIVATE pqc_framework)

add_executable(pqc_list_algs pqc_list_algs.c)
target_link_libraries(pqc_list_algs PRIVATE pqc_framework)

add_executable(pqc_bench_algo pqc_bench_algo.c)
target_link_libraries(pqc_bench_algo PRIVATE pqc_framework)

if(PQC_ENABLE_QUIC)
    add_executable(pqc_bench_quic pqc_bench_quic.c)
    target_link_libraries(pqc_bench_quic PRIVATE pqc_framework)
endif()
