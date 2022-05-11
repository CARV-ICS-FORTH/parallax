set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${CMAKE_SOURCE_DIR}/lib)

if(BUILD_TESTING)
  set(LIB_TEST_FILES
      test_recovery.c
      test_index_node.c
      test_scans.c
      test_dirty_scans.c
      test_options.c
      test_sanitizers.c
      simple_test_delete.c
      test_gc.c
      test_leaf_root_delete_get_scan.c
      test_region_allocations.c
      test_par_format.c
      test_par_put_serialized.c)

  set_source_files_properties(${LIB_TEST_FILES} COMPILE_FLAGS "-O3")

  add_executable(test_index_node test_index_node.c arg_parser.c)
  target_link_libraries(test_index_node "${PROJECT_NAME}" ${DEPENDENCIES})

  add_executable(test_scans test_scans.c)
  target_link_libraries(test_scans "${PROJECT_NAME}" ${DEPENDENCIES})

  add_executable(test_dirty_scans test_dirty_scans.c arg_parser.c)
  target_link_libraries(test_dirty_scans "${PROJECT_NAME}" ${DEPENDENCIES})

  add_test(NAME test_index_node COMMAND $<TARGET_FILE:test_index_node>
                                        --file=${FILEPATH})

  add_test(
    NAME test_dirty_scans_sd_greater
    COMMAND
      $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH} --num_of_kvs=4000000
      --scan_size=30 --workload=All_scan_greater --kv_mix=sd)

  add_test(
    NAME test_dirty_scans_small
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=s)
  add_test(
    NAME test_dirty_scans_medium
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=m)
  add_test(
    NAME test_dirty_scans_large
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=l)
  add_test(
    NAME test_dirty_scans_smalld
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=sd)
  add_test(
    NAME test_dirty_scans_mediumd
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=md)
  add_test(
    NAME test_dirty_scans_larged
    COMMAND $<TARGET_FILE:test_dirty_scans> --file=${FILEPATH}
            --num_of_kvs=4000000 --scan_size=30 --workload=All --kv_mix=ld)

  add_test(NAME test_dirty_scans_smallp COMMAND test_dirty_scans.sh s)
  add_test(NAME test_dirty_scans_mediump COMMAND test_dirty_scans.sh m)
  add_test(NAME test_dirty_scans_largep COMMAND test_dirty_scans.sh l)
  add_test(NAME test_dirty_scans_smalldp COMMAND test_dirty_scans.sh sd)
  add_test(NAME test_dirty_scans_mediumdp COMMAND test_dirty_scans.sh md)
  add_test(NAME test_dirty_scans_largedp COMMAND test_dirty_scans.sh ld)

  add_executable(test_recovery test_recovery.c)
  target_link_libraries(test_recovery "${PROJECT_NAME}" ${DEPENDENCIES})

  add_executable(test_options test_options.c)
  target_link_libraries(test_options "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(NAME test_options COMMAND $<TARGET_FILE:test_options>)

  set_source_files_properties(test_sanitizers.c COMPILE_FLAGS "-O0")
  add_executable(test_sanitizers test_sanitizers.c)
  add_test(NAME test_sanitizers COMMAND $<TARGET_FILE:test_sanitizers>)

  add_executable(test_gc test_gc.c arg_parser.c)
  target_link_libraries(test_gc "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(NAME test_gc COMMAND $<TARGET_FILE:test_gc> --file=${FILEPATH}
                                --num_of_kvs=1000000)

  add_executable(test_mixes test_mixes.c arg_parser.c)
  target_link_libraries(test_mixes "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(
    NAME test_mixes_all_medium
    COMMAND
      $<TARGET_FILE:test_mixes> --file=/tmp/kv_store.dat --num_of_kvs=1000000
      --small_kv_percentage=0 --medium_kv_percentage=100 --big_kv_percentage=0)
  add_test(
    NAME test_mixes_most_small_few_medium
    COMMAND
      $<TARGET_FILE:test_mixes> --file=/tmp/kv_store.dat --num_of_kvs=1000000
      --small_kv_percentage=99 --medium_kv_percentage=1 --big_kv_percentage=0)

  add_executable(simple_test_delete simple_test_delete.c arg_parser.c)
  target_link_libraries(simple_test_delete "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(NAME simple_test_delete
           COMMAND $<TARGET_FILE:simple_test_delete> --file=${FILEPATH}
                   --num_of_kvs=1000000)

  add_executable(
    test_leaf_root_delete_get_scan test_leaf_root_delete_get_scan.c
                                   arg_parser.c ../lib/common/common.c)
  target_link_libraries(test_leaf_root_delete_get_scan "${PROJECT_NAME}"
                        ${DEPENDENCIES})
  add_test(NAME test_leaf_root_delete_get_scan
           COMMAND $<TARGET_FILE:test_leaf_root_delete_get_scan>
                   --file=${FILEPATH})

  add_executable(
    test_region_allocations
    test_region_allocations.c ../lib/allocator/allocator.c
    ../lib/allocator/djb2.c ../lib/allocator/redo_undo_log.c)
  target_link_libraries(test_region_allocations "${PROJECT_NAME}"
                        ${DEPENDENCIES})
  add_test(NAME test_region_allocations
           COMMAND $<TARGET_FILE:test_region_allocations>)

  add_executable(
    test_redo_undo_log
    test_redo_undo_log.c ../lib/allocator/allocator.c ../lib/allocator/djb2.c
    ../lib/allocator/redo_undo_log.c arg_parser.c)
  target_link_libraries(test_redo_undo_log "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(NAME test_redo_undo_log COMMAND $<TARGET_FILE:test_redo_undo_log>
                                           --file=${FILEPATH} --num_threads=4)

  add_executable(test_optional_logging test_optional_logging.c)
  add_test(NAME test_optional_logging
           COMMAND $<TARGET_FILE:test_optional_logging>)

  add_executable(test_par_format test_par_format.c arg_parser.c)
  target_link_libraries(test_par_format "${PROJECT_NAME}" ${DEPENDENCIES})
  add_test(NAME test_par_format COMMAND $<TARGET_FILE:test_par_format>
                                        --file=${FILEPATH})

  add_executable(test_par_put_serialized test_par_put_serialized.c arg_parser.c)
  target_link_libraries(test_par_put_serialized "${PROJECT_NAME}"
                        ${DEPENDENCIES})
  add_test(NAME test_par_put_serialized
           COMMAND $<TARGET_FILE:test_par_put_serialized> --file=${FILEPATH})

  add_subdirectory(Surrogates)
endif()
