# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_C_FLAGS
      "-Wstrict-prototypes -Wall -Wextra -std=gnu11 -fPIC ${CMAKE_C_FLAGS}"
  )# -Werror
  set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -Og ${CMAKE_C_FLAG_DEBUG}")
endif()

if(CMAKE_BUILD_TYPE EQUAL "Release")
  set(CMAKE_C_FLAGS_RELEASE "-O2 -finline-functions -DNDEBUG") # -Werror
endif()

set(LOG ${CMAKE_BINARY_DIR}/external-deps/log/src/log.c)
file(
  GLOB_RECURSE KREON_C_SOURCE_FILES ${CMAKE_SOURCE_DIR}/kreon_lib/allocator/*.c
  ${CMAKE_SOURCE_DIR}/kreon_lib/btree/*.c
  ${CMAKE_SOURCE_DIR}/kreon_lib/scanner/*.c)

# list(REMOVE_ITEM KREON_C_SOURCE_FILES
# "${CMAKE_SOURCE_DIR}/kreon/btree/replica.c")
list(APPEND KREON_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND KREON_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/min_max_heap.c")
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
  btree/delete.c
  btree/gc.c
  scanner/stack.c
  scanner/scanner.c
  ../utilities/spin_loop.c
  ../utilities/min_max_heap.c
  ../utilities/list.c
  ../utilities/min_max_heap.c
  ${LOG})

set_target_properties(kreonr PROPERTIES COMPILE_DEFINITIONS "KREONR")

# Kreon with replication disabled
add_library(kreon STATIC ${KREON_C_SOURCE_FILES} ${LOG})

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")

# mkfs for kreon volumes
add_executable(
  mkfs.kreon
  allocator/mkfs_Eutropia.c
  allocator/allocator.c
  allocator/persistent_operations.c
  btree/segment_allocator.c
  ../utilities/spin_loop.c
  ../utilities/list.c
  ${LOG})

install(TARGETS kreonr kreon mkfs.kreon)
