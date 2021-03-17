set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LIB "${PROJECT_NAME}")

set(LIB_C_SOURCE_FILES
    allocator/allocator.c
    allocator/persistent_operations.c
    allocator/recovery.c
    btree/btree.c
    btree/compaction_daemon.c
    btree/dynamic_leaf.c
    btree/gc.c
    btree/segment_allocator.c
    btree/set_options.c
    scanner/min_max_heap.c
    scanner/scanner.c
    scanner/stack.c)

list(APPEND LIB_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND LIB_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/list.c")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set_source_files_properties(LIB_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS
                                                            "${CMAKE_C_FLAGS}")
else()
  set_source_files_properties(
    LIB_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_RELEASE}")
endif()
add_library(${LIB} ${LIB_C_SOURCE_FILES})
set_property(TARGET ${LIB} PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(${LIB} PRIVATE ${DEPENDENCIES})

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")
# mkfs to initialize volumes
add_executable(
  mkfs.${LIB}
  allocator/mkfs_parallax.c
  allocator/allocator.c
  allocator/persistent_operations.c
  btree/segment_allocator.c
  btree/set_options.c
  ../utilities/spin_loop.c
  ../utilities/list.c)

target_link_libraries(mkfs.${LIB} PRIVATE ${DEPENDENCIES})

install(
  TARGETS ${LIB} mkfs.${LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
set_target_properties(${LIB} PROPERTIES OUTPUT_NAME ${LIB})

find_program(iwyu_path NAMES include-what-you-use iwyu iwyu-tool)
if(iwyu_path)
  set_property(TARGET ${LIB} PROPERTY C_INCLUDE_WHAT_YOU_USE ${iwyu_path})
else()
  message("Could not find the program include-what-you-use")
endif()
