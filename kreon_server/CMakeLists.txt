# File: TucanaServer/CMakeLists.txt
# Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXE_LINKER_FLAGS "-Wl,--no-as-needed -lm -pthread -lnuma -libverbs -lrdmacm -lzookeeper_mt")
add_definitions(-DKREONR)

add_library(client STATIC zk_client.c zk_string_vector.c
  network_data.c network_data_client.c regions.c
  messages.c client_regions.c client_scanner.c
	client_regions_manager.c djb2.c
)

add_executable(kreon_server server.c globals.c zk_string_vector.c regions_manager.c
  network_data.c zk_server.c network_data_server.c server_regions.c
	regions.c messages.c  storage_devices.c ../kreon_rdma/rdma.c
  stats.c
)
target_link_libraries(kreon_server kreon_rdma_lib kreon_server_lib)

add_executable(create_regions create_regions.c zk_string_vector.c
	network_data.c regions.c globals.c ../utilities/queue.c ../utilities/simple_concurrent_list.c
  ../utilities/spin_loop.c ../utilities/circular_buffer.c
)
target_link_libraries(create_regions kreon_rdma_lib)

# FIXME put_get_test and scan_test don't compile
#add_executable(put_get_test tests/put_get.c zk_string_vector.c tu_network_data.c
  #zk_server.c tu_network_data_server.c server_regions.c tucana_regions.c
  #tucana_messages.c tucana_storage_devices.c rbtree.c  zk_client.c
  #zk_string_vector.c tu_network_data.c tu_network_data_client.c
  #client_tucana_regions.c
#)
#target_link_libraries(put_get_test turdma)

#add_executable(scan_test tests/scan.c zk_string_vector.c tu_network_data.c zk_server.c
  #tu_network_data_server.c server_regions.c tucana_regions.c tucana_messages.c
  #tucana_storage_devices.c rbtree.c  zk_client.c zk_string_vector.c
  #tu_network_data.c tu_network_data_client.c client_tucana_regions.c
  #client_scanner.c
#)
#add_executable(scan_test tests/scan.c)
#target_link_libraries(scan_test tuclient turdma)

#add_executable(fake_client fake_client.c client_regions_manager.c rbtree.c
#  zk_client.c zk_string_vector.c tu_network_data.c tu_network_data_client.c
#	tucana_regions.c tucana_messages.c client_tucana_regions.c client_scanner.c ../TuRDMA/tu_rdma.c
#)
#target_link_libraries(fake_client turdma)
