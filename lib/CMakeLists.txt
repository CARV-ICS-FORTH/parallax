# Copyright [2021] [FORTH-ICS]
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LIB "${PROJECT_NAME}")

option(
  RUN_IWYU
  "Run include-what-you-use on the source files of the key-value store library."
  OFF)

set(LIB_C_SOURCE_FILES
    allocator/allocator.c
    allocator/log_structures.c
    allocator/kv_format.c
    allocator/region_log.c
    allocator/persistent_operations.c
    allocator/djb2.c
    api/parallax.c
    btree/btree.c
    btree/index_node.c
    btree/compaction/compaction_daemon.c
    btree/compaction/compaction_worker.c
    btree/dynamic_leaf.c
    btree/compaction/device_level.c
    btree/compaction/dev_leaf.c
    btree/compaction/fractal_leaf.c
    btree/compaction/fractal_index.c
    btree/compaction/dev_index.c
    btree/compaction/sst.c
    btree/compaction/threadpool.c
    btree/gc.c
    btree/medium_log_LRU_cache.c
    btree/segment_allocator.c
    btree/set_options.c
    btree/kv_pairs.c
    btree/key_splice.c
    btree/lsn.c
    common/common.c
    scanner/min_max_heap.c
    scanner/scanner.c
    scanner/L0_scanner.c
    scanner/stack.c
    parallax_callbacks/parallax_callbacks.c)

list(APPEND LIB_C_SOURCE_FILES
     "$CACHE{parallax_SOURCE_DIR}/utilities/spin_loop.c")
list(APPEND LIB_C_SOURCE_FILES "$CACHE{parallax_SOURCE_DIR}/utilities/list.c")
list(APPEND LIB_C_SOURCE_FILES
     "$CACHE{parallax_SOURCE_DIR}/utilities/dups_list.c")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set_source_files_properties(LIB_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS
                                                            "${CMAKE_C_FLAGS}")
else()
  set_source_files_properties(
    LIB_C_SOURCE_FILES PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_RELEASE}")
endif()
add_library(${LIB} ${LIB_C_SOURCE_FILES})
target_link_libraries(${LIB} ${DEPENDENCIES})
set_target_properties(
  ${LIB} PROPERTIES PUBLIC_HEADER
                    "${CMAKE_CURRENT_SOURCE_DIR}/include/parallax/parallax.h")

target_include_directories(${LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/")

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")
# kv_format utility
add_executable(kv_format.${LIB} allocator/kv_format.c common/common.c)
target_compile_definitions(kv_format.${LIB} PUBLIC -DSTANDALONE_FORMAT)
target_link_libraries(kv_format.${LIB} PRIVATE ${DEPENDENCIES})

install(
  TARGETS ${LIB} kv_format.${LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(FILES include/parallax/parallax.h include/parallax/structures.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

set_target_properties(${LIB} PROPERTIES OUTPUT_NAME ${LIB})

if(RUN_IWYU STREQUAL "ON")
  find_program(iwyu_path NAMES include-what-you-use iwyu iwyu-tool)
  if(iwyu_path)
    set_property(TARGET ${LIB} PROPERTY C_INCLUDE_WHAT_YOU_USE ${iwyu_path})
  else()
    message("Could not find the program include-what-you-use")
  endif()
endif()
