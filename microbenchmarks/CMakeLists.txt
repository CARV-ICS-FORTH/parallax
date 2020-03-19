# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



set_source_files_properties(throughput_bench.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "-lm -lrt -pthread -lnuma -libverbs -lrdmacm  -lzookeeper_mt")
# add_definitions(-DKREONR -DTESTS)

add_library(
  runtime STATIC
  ../kreon/allocator/recovery.c
  ../utilities/spin_loop.c
  ../kreon/allocator/allocator.c
  ../kreon/btree/btree.c
	../utilities/stack.c
  ../utilities/min_max_heap.c
  ../utilities/simple_concurrent_list.c
  ../utilities/queue.c
  ../kreon/scanner/scanner.c
  ../utilities/list.c
  ../utilities/circular_buffer.c
  ../TuRDMA/tu_rdma.c
  ../TuRDMA/memory_region_pool.c
  ../TucanaServer/tucanaserver.c
  ../TucanaServer/stats.c
  ../TucanaServer/globals.c
  ../TucanaServer/zk_string_vector.c
  ../TucanaServer/regions_manager.c
  ../TucanaServer/tu_network_data.c
  ../TucanaServer/zk_server.c
  ../TucanaServer/tu_network_data_server.c
  ../TucanaServer/server_regions.c
  ../TucanaServer/tucana_regions.c
  ../TucanaServer/tucana_messages.c
  ../TucanaServer/tucana_storage_devices.c)



add_executable(throughput_bench throughput_bench.c ../TucanaServer/globals.c)
target_link_libraries(throughput_bench kreon_client turdma)
