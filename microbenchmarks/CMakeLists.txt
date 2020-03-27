# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set_source_files_properties(throughput_bench.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "-Wl,--no-as-needed -lm -lrt -pthread -lnuma -libverbs -lrdmacm  -lzookeeper_mt")

add_executable(throughput_bench throughput_bench.c ../kreon_server/globals.c)
target_link_libraries(throughput_bench kreon_client kreon_rdma kreonr)

add_executable(latency_bench throughput_bench.c ../kreon_server/globals.c ../utilities/latency_monitor.c)
target_link_libraries(latency_bench kreon_client kreon_rdma kreonr)
target_compile_definitions(latency_bench PUBLIC "LATENCY_MONITOR_ENABLED=1")