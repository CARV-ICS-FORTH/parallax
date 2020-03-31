# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set_source_files_properties(test_streaming_btree.c PROPERTIES COMPILE_FLAGS
                                                              "-O3")

set_source_files_properties(test_circular_buffer.c PROPERTIES COMPILE_FLAGS
                                                              "-O3")

set_source_files_properties(test_scans.c PROPERTIES COMPILE_FLAGS "-O3")

set_source_files_properties(test_krc_scans.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "-Wl,-no-as-needed -lm -lrt -pthread -lnuma") # -libverbs -lrdmacm
                                                       # -lzookeeper_mt
# add_definitions(-DKREONR -DTESTS)

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

add_executable(test_region_watchers test_region_watchers.c ../kreon_server/create_regions_utils.c)
target_link_libraries(test_region_watchers kreon_client kreon_rdma kreonr)
  set_target_properties(
    test_region_watchers
    PROPERTIES LINK_FLAGS "-Wl,-no-as-needed -pthread -lm -lzookeeper_mt -lnuma -lrdmacm -libverbs"
              COMPILE_DEFINITIONS "KREON_DISTRIBUTED")


add_executable(test_krc_api test_krc_api.c ../kreon_server/create_regions_utils.c)
target_link_libraries(test_krc_api kreon_client kreon_rdma kreonr)
  set_target_properties(
    test_krc_api
    PROPERTIES LINK_FLAGS "-Wl,-no-as-needed -pthread -lm -lzookeeper_mt -lnuma -lrdmacm -libverbs"
              COMPILE_DEFINITIONS "KREON_DISTRIBUTED")

add_executable(test_circular_buffer test_circular_buffer.c
                                    ../utilities/circular_buffer.c)


