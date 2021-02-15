include_directories(${CMAKE_SOURCE_DIR}/lib)

set(LIB_TEST_FILES test_deletes test_recovery.c test_scans.c test_dirty_scans.c
                   test_options.c)

set_source_files_properties(${LIB_TEST_FILES} COMPILE_FLAGS "-O3")

add_executable(test_scans test_scans.c)
target_link_libraries(test_scans "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_dirty_scans test_dirty_scans.c)
target_link_libraries(test_dirty_scans "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_spillscans test_spillscanner.c)
target_link_libraries(test_spillscans "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_deletes test_deletes.c)
target_link_libraries(test_deletes "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_recovery test_recovery.c)
target_link_libraries(test_recovery "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_spills test_spills.c)
target_link_libraries(test_spills "${PROJECT_NAME}" ${DEPENDENCIES})

add_executable(test_options test_options.c)
target_link_libraries(test_options "${PROJECT_NAME}" ${DEPENDENCIES})
add_test(NAME test_options COMMAND $<TARGET_FILE:test_options>)

add_subdirectory(Surrogates)
