# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set_source_files_properties(test_streaming_btree.c PROPERTIES COMPILE_FLAGS
                                                              "-O3")

set_source_files_properties(test_circular_buffer.c PROPERTIES COMPILE_FLAGS
                                                              "-O3")

set_source_files_properties(test_scans.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "-lm -lrt -pthread -lnuma") # -libverbs -lrdmacm
                                                       # -lzookeeper_mt
# add_definitions(-DKREONR -DTESTS)

add_library(
  runtime STATIC
  ../kreon_lib/allocator/recovery.c
  ../utilities/spin_loop.c
  ../kreon_lib/allocator/persistent_operations.c
  ../kreon_lib/allocator/allocator.c
  ../kreon_lib/btree/segment_allocator.c
  ../kreon_lib/btree/btree.c
	../utilities/stack.c
  ../utilities/min_max_heap.c
  ../utilities/simple_concurrent_list.c
  ../utilities/queue.c
  ../kreon_lib/scanner/scanner.c
  ../utilities/list.c
  ../utilities/circular_buffer.c
  ../kreon_rdma/rdma.c
  ../kreon_rdma/memory_region_pool.c
  ../kreon_server/server.c
  ../kreon_server/stats.c
  ../kreon_server/globals.c
  ../kreon_server/zk_string_vector.c
  ../kreon_server/regions_manager.c
  ../kreon_server/network_data.c
  ../kreon_server/zk_server.c
  ../kreon_server/network_data_server.c
  ../kreon_server/server_regions.c
  ../kreon_server/replica_utilities.c
  ../kreon_server/regions.c
  ../kreon_server/messages.c
  ../kreon_server/storage_devices.c)

#add_executable(streaming_btree_test test_streaming_btree.c)
#target_link_libraries(streaming_btree_test runtime)

add_executable(test_scans test_scans.c)
target_link_libraries(test_scans kreon)

add_executable(test_spillscans test_spillscanner.c)
target_link_libraries(test_spillscans kreon)

add_executable(test_deletes test_deletes.c)
target_link_libraries(test_deletes kreon)

add_executable(test_spills test_spills.c)
target_link_libraries(test_spills kreon)

add_executable(test_circular_buffer test_circular_buffer.c
                                    ../utilities/circular_buffer.c)


