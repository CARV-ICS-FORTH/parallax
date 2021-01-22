# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LIB "${PROJECT_NAME}")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_C_FLAGS
      "-Wstrict-prototypes -Wall -Wextra -std=gnu11 -fPIC ${CMAKE_C_FLAGS}"
  )# -Werror
  set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -Og ${CMAKE_C_FLAGS_DEBUG}")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  set(CMAKE_C_FLAGS_RELEASE
      "-flto -fwhopr -funit-at-a-time -fprefetch-loop-arrays -fpeel-loops -O2 -finline-functions -DNDEBUG ${CMAKE_C_FLAGS_RELEASE}"
  ) # -Werror
endif()

set(LIB_C_SOURCE_FILES
    allocator/allocator.c
    allocator/persistent_operations.c
    allocator/recovery.c
    btree/btree.c
    btree/compaction_daemon.c
    btree/delete.c
    btree/dynamic_leaf.c
    btree/gc.c
    btree/segment_allocator.c
    btree/static_leaf.c
    scanner/min_max_heap.c
    scanner/scanner.c
    scanner/stack.c)

list(APPEND LIB_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND LIB_C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/utilities/list.c")

set_source_files_properties(
  LIB_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS
                                "${CMAKE_C_FLAGS_RELEASE} ${CMAKE_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed -lrt -lm -pthread -lnuma -lutil"
)

add_library(${LIB} ${LIB_C_SOURCE_FILES})
set_property(TARGET ${LIB} PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(${LIB} PRIVATE ${DEPENDENCIES})

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")

set_source_files_properties(btree/delete.c PROPERTIES COMPILE_FLAGS "-w")

# mkfs to initialize volumes
add_executable(
  mkfs.${LIB}
  allocator/mkfs_Eutropia.c allocator/allocator.c
  allocator/persistent_operations.c btree/segment_allocator.c
  ../utilities/spin_loop.c ../utilities/list.c)

target_link_libraries(mkfs.${LIB} PRIVATE log)

install(
  TARGETS ${LIB} mkfs.${LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
set_target_properties(${LIB} PROPERTIES OUTPUT_NAME ${LIB})
