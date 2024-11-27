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

option(MOCKUP "Enable mockup implementation for Parallax" OFF)
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

if(MOCKUP)
  list(APPEND LIB_C_SOURCE_FILES
       ../net_interface/portals_server/parallax_mockup.c)
else()
  list(APPEND LIB_C_SOURCE_FILES api/parallax.c)
endif()

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
target_include_directories(${LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/")

set_source_files_properties(allocator/spin_loop.c PROPERTIES COMPILE_FLAGS
                                                             "-O0")
# kv_format utility
add_executable(kv_format.${LIB} allocator/kv_format.c common/common.c)
target_compile_definitions(kv_format.${LIB} PUBLIC -DSTANDALONE_FORMAT)
target_link_libraries(kv_format.${LIB} PRIVATE ${DEPENDENCIES})

add_executable(
  server.${LIB}
  ../net_interface/server/parallax_server.c
  ../net_interface/server/server_handle.c
  ../net_interface/par_net/par_net_open.c
  ../net_interface/par_net/par_net_put.c
  ../net_interface/par_net/par_net_delete.c
  ../net_interface/par_net/par_net_get.c
  ../net_interface/par_net/par_net_close.c
  ../net_interface/par_net/par_net_scan.c
  ../net_interface/par_net/par_net_sync.c)
target_compile_definitions(server.${LIB} PUBLIC -DSTANDALONE_FORMAT)
target_link_libraries(server.${LIB} PRIVATE ${LIB} ${DEPENDENCIES})

install(
  TARGETS ${LIB} kv_format.${LIB} server.${LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(FILES include/parallax/parallax.h include/parallax/structures.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

set_target_properties(${LIB} PROPERTIES OUTPUT_NAME ${LIB})
set_target_properties(server.${LIB} PROPERTIES OUTPUT_NAME ${LIB}_server)

# ######### PORTALS SERVER !!! ###########

option(PORTALS_LIB_DIR "Path to the Portals library" "")
option(QUEUE_LIB "Path to the sim-universal-construction library" "")
option(QUEUE_INCLUDE_DIR
       "Path to the sim-universal-construction include directory" "")

find_library(
  QUEUE_LIB_FOUND
  NAMES concurrent
  PATHS ${QUEUE_LIB})

find_library(
  PORTALS_LIB
  NAMES portals
  PATHS ${PORTALS_LIB_DIR})

if(PORTALS_LIB AND QUEUE_LIB_FOUND)
  add_definitions(-DPARALLAX_PORTALS)

  message(STATUS "Portals library for server found at : ${PORTALS_LIB}")
  message(
    STATUS
      "sim-universal-construction library for server found at: ${QUEUE_LIB_FOUND}"
  )

  set(PORT_LIB "portals_${PROJECT_NAME}_server")

  add_executable(
    ${PORT_LIB}
    ../net_interface/portals_server/portals_server.c
    ../net_interface/portals_server/portals_server_handle.c
    ../net_interface/portals_server/portals_worker.c
    ../net_interface/portals_server/worker_request.c
    ../net_interface/par_net/par_net_open.c
    ../net_interface/par_net/par_net_put.c
    ../net_interface/par_net/par_net_delete.c
    ../net_interface/par_net/par_net_get.c
    ../net_interface/par_net/par_net_close.c
    ../net_interface/par_net/par_net_scan.c
    ../net_interface/par_net/par_net_sync.c)

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set_target_properties(${PORT_LIB} PROPERTIES COMPILE_FLAGS
                                                 "${CMAKE_C_FLAGS}")
  else()
    set_target_properties(${PORT_LIB} PROPERTIES COMPILE_FLAGS
                                                 "${CMAKE_C_FLAGS_RELEASE}")
  endif()

  set_target_properties(
    ${PORT_LIB}
    PROPERTIES PUBLIC_HEADER
               "${CMAKE_CURRENT_SOURCE_DIR}/include/parallax/parallax.h")

  target_include_directories(
    ${PORT_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../net_interface/par_net")
  target_include_directories(${PORT_LIB}
                             PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/")
  target_include_directories(${PORT_LIB} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/")
  target_include_directories(${PORT_LIB} PUBLIC "${PORTALS_INCLUDE_DIR}")

  if(NOT QUEUE_INCLUDE_DIR)
    get_filename_component(QUEUE_LIB_DIR ${QUEUE_LIB_FOUND} DIRECTORY)
    set(QUEUE_INCLUDE_DIR "${QUEUE_LIB_DIR}/../includes")
  endif()

  if(EXISTS "${QUEUE_INCLUDE_DIR}")
    message(
      STATUS
        "Found include directory for sim-universal-construction at: ${QUEUE_INCLUDE_DIR}"
    )
  else()
    message(
      FATAL_ERROR
        "Could not find the sim-universal-construction include directory")
  endif()

  get_filename_component(QUEUE_LIB_DIR ${QUEUE_LIB_FOUND} DIRECTORY)
  set(QUEUE_LIBCONC_DIR "${QUEUE_LIB_DIR}/../includes")

  target_include_directories(${PORT_LIB} PUBLIC "${QUEUE_INCLUDE_DIR}")
  target_link_libraries(${PORT_LIB} log yaml ${PORTALS_LIB} ${LIB}
                        ${QUEUE_LIB_FOUND})

  install(
    TARGETS ${PORT_LIB}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
elseif()
  message(
    WARNING
      "Portals library or sim-universal-construction not found, stoping installation for portals server"
  )
endif()

# ######### END OF PORTALS SERVER !!! ###########

if(RUN_IWYU STREQUAL "ON")
  find_program(iwyu_path NAMES include-what-you-use iwyu iwyu-tool)
  if(iwyu_path)
    set_property(TARGET ${LIB} PROPERTY C_INCLUDE_WHAT_YOU_USE ${iwyu_path})
    set_property(TARGET server.${LIB} PROPERTY C_INCLUDE_WHAT_YOU_USE
                                               ${iwyu_path})
  else()
    message("Could not find the program include-what-you-use")
  endif()
endif()
