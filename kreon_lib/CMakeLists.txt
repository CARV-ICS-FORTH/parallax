# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(KREON_LIB "kreon")
set(KREON_LIB_SHARED "kreon-shared")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_C_FLAGS
      "-Wstrict-prototypes -Wall -Wextra -std=gnu11 -fPIC ${CMAKE_C_FLAGS}"
  )# -Werror
  set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -Og ${CMAKE_C_FLAGS_DEBUG}")
endif()

if(CMAKE_BUILD_TYPE EQUAL "Release")
  set(CMAKE_C_FLAGS_RELEASE
      "-flto -fwhopr -funit-at-a-time -fprefetch-loop-arrays -fpeel-loops -O2 -finline-functions -DNDEBUG ${CMAKE_C_FLAGS_RELEASE}"
  ) # -Werror
endif()

file(
  GLOB_RECURSE KREON_C_SOURCE_FILES ${CMAKE_SOURCE_DIR}/kreon_lib/allocator/*.c
  ${CMAKE_SOURCE_DIR}/kreon_lib/btree/*.c
  ${CMAKE_SOURCE_DIR}/kreon_lib/scanner/*.c)

# list(REMOVE_ITEM KREON_C_SOURCE_FILES
list(APPEND KREON_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND KREON_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/list.c")
set_source_files_properties(
  KREON_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS
                                  "${CMAKE_C_FLAGS_RELEASE} ${CMAKE_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--no-as-needed -lrt -lm -pthread -lnuma")

# Kreon with replication enabled
add_library(
  kreonr STATIC
  allocator/recovery.c
  allocator/allocator.c
  allocator/persistent_operations.c
  btree/segment_allocator.c
  btree/btree.c
  btree/compaction_daemon.c
  btree/delete.c
  btree/gc.c
  scanner/stack.c
  scanner/scanner.c
  scanner/min_max_heap.c
  ../utilities/spin_loop.c
  ../utilities/list.c)

add_library(
  kreonr-shared SHARED
  allocator/recovery.c
  allocator/allocator.c
  allocator/persistent_operations.c
  btree/segment_allocator.c
  btree/btree.c
  btree/compaction_daemon.c
  btree/delete.c
  btree/gc.c
  scanner/stack.c
  scanner/min_max_heap.c
  scanner/scanner.c
  ../utilities/spin_loop.c
  ../utilities/list.c)

set_target_properties(kreonr PROPERTIES COMPILE_DEFINITIONS "KREONR")

# Kreon with replication disabled
add_library(${KREON_LIB} STATIC ${KREON_C_SOURCE_FILES})
add_library(${KREON_LIB_SHARED} SHARED ${KREON_C_SOURCE_FILES})

set_property(TARGET ${KREON_LIB} PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET ${KREON_LIB_SHARED} PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${KREON_LIB} log mba)
target_link_libraries(${KREON_LIB_SHARED} log-shared mba-shared)

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")

# mkfs for kreon volumes
add_executable(
  mkfs.kreon
  allocator/mkfs_Eutropia.c allocator/allocator.c
  allocator/persistent_operations.c btree/segment_allocator.c
  ../utilities/spin_loop.c ../utilities/list.c)

target_link_libraries(mkfs.kreon log)

if(KREON_BUILD_CPACK)
  install(
    TARGETS ${KREON_LIB} ${KREON_LIB_SHARED} mkfs.kreon kreonr-shared
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
  set_target_properties(${KREON_LIB} PROPERTIES OUTPUT_NAME kreon)
  set_target_properties(${KREON_LIB_SHARED} PROPERTIES OUTPUT_NAME kreon)
  set_target_properties(kreonr-shared PROPERTIES OUTPUT_NAME kreonr)
endif()
