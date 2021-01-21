# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set_source_files_properties(test_deletes.c PROPERTIES COMPILE_FLAGS "-O3")
set_source_files_properties(test_recovery.c PROPERTIES COMPILE_FLAGS "-O3")

set_source_files_properties(test_scans.c PROPERTIES COMPILE_FLAGS "-O3")
set_source_files_properties(test_dirty_scans.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "-Wl,-no-as-needed -lm -lrt -pthread -lnuma")

# add_executable(streaming_btree_test test_streaming_btree.c)
# target_link_libraries(streaming_btree_test runtime)

add_executable(test_scans test_scans.c)
target_link_libraries(test_scans kreon)

add_executable(test_dirty_scans test_dirty_scans.c)
target_link_libraries(test_dirty_scans kreon)

add_executable(test_spillscans test_spillscanner.c)
target_link_libraries(test_spillscans kreon)

add_executable(test_deletes test_deletes.c)
target_link_libraries(test_deletes kreon)

add_executable(test_recovery test_recovery.c)
target_link_libraries(test_recovery kreon)

add_executable(test_spills test_spills.c)
target_link_libraries(test_spills kreon)
