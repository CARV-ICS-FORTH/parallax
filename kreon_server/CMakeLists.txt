# File: TucanaServer/CMakeLists.txt Author: Michalis Vardoulakis
# <mvard@ics.forth.gr>

set(CMAKE_EXE_LINKER_FLAGS
    "-Wl,-no-as-needed -lm -pthread -lnuma -libverbs -lrdmacm -lzookeeper_mt")
add_definitions(-DKREONR)

add_library(
  kreon_client STATIC
  zk_client.c
  zk_string_vector.c
  network_data.c
  network_data_client.c
  regions.c
  messages.c
  client_regions.c
  client_scanner.c
  client_regions_manager.c
  ../kreon_rdma_client/kreon_rdma_client.c
  ../kreon_server/globals.c
  ../kreon_server/client_regions.c
  ../kreon_rdma_client/kreon_rdma_client.c
  djb2.c)

add_library(
  kreon_client-shared SHARED
  zk_client.c
  zk_string_vector.c
  network_data.c
  network_data_client.c
  regions.c
  messages.c
  client_regions.c
  client_scanner.c
  client_regions_manager.c
  ../kreon_rdma_client/kreon_rdma_client.c
  ../kreon_server/globals.c
  ../kreon_server/client_regions.c
  ../kreon_rdma_client/kreon_rdma_client.c
  djb2.c)

add_executable(
  kreon_server
  server.c
  replica_utilities.c
  globals.c
  zk_string_vector.c
  regions_manager.c
  network_data.c
  zk_server.c
  network_data_server.c
  server_regions.c
  regions.c
  messages.c
  storage_devices.c
  ../kreon_rdma/rdma.c
  stats.c)
target_link_libraries(kreon_server kreon_rdma kreonr)

add_executable(
  create_regions
  create_regions.c
  create_regions_utils.c
  zk_string_vector.c
  network_data.c
  regions.c
  globals.c
  ../utilities/queue.c
  ../utilities/simple_concurrent_list.c
  ../utilities/spin_loop.c
  ../utilities/circular_buffer.c)
target_link_libraries(create_regions kreon_rdma kreonr)

# FIXME put_get_test and scan_test don't compile add_executable(put_get_test
# tests/put_get.c zk_string_vector.c network_data.c zk_server.c
# network_data_server.c server_regions.c regions.c messages.c storage_devices.c
# rbtree.c  zk_client.c zk_string_vector.c network_data.c network_data.client.c
# client_regions.c ) target_link_libraries(put_get_test kreon_rdma)

# add_executable(scan_test tests/scan.c zk_string_vector.c network_data.c
# zk_server.c network_data_server.c server_regions.c regions.c messages.c
# storage_devices.c rbtree.c  zk_client.c zk_string_vector.c network_data.c
# network_data.client.c client_regions.c client_scanner.c )
# add_executable(scan_test tests/scan.c) target_link_libraries(scan_test
# tuclient kreon_rdma)

# add_executable(fake_client fake_client.c client_regions_manager.c rbtree.c
# zk_client.c zk_string_vector.c network_data.c network_data.client.c regions.c
# messages.c client_regions.c client_scanner.c ../TuRDMA/rdma.c )
# target_link_libraries(fake_client kreon_rdma)
if(KREON_BUILD_CPACK)
  install(
    TARGETS kreon_client-shared kreon_server create_regions
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()
