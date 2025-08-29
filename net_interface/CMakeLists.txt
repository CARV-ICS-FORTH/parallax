set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(NET_LIB "${PROJECT_NAME}_net_lib")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(NET_LIB_SOURCE_FILES
    par_net/par_net_put.c
    par_net/par_net_open.c
    par_net/par_net_delete.c
    par_net/par_net_get.c
    par_net/par_net_close.c
    par_net/par_net_scan.c
    par_net/par_net_sync.c
    ../lib/api/parallax_client_lib.c
    ../lib/btree/key_splice.c
    ../lib/btree/set_options.c
    ../lib/btree/kv_pairs.c
    ../lib/common/common.c)

add_library(${NET_LIB} SHARED ${NET_LIB_SOURCE_FILES})

set_target_properties(
  ${NET_LIB}
  PROPERTIES PUBLIC_HEADER
             "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h")

target_include_directories(${NET_LIB}
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include")

if(USE_INFINIBAND)
  find_library(RDMA_LIB NAMES rdmacm PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu)
  find_library(IBVERBS_LIB NAMES ibverbs PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu)

  option(USE_IBV_CQ_EVENT "Use ibv_get_cq_event instead of spinning" OFF)

  if(RDMA_LIB AND IBVERBS_LIB)
    message(STATUS "InfiniBand libraries found: ${RDMA_LIB}, ${IBVERBS_LIB}")
    target_link_libraries(${NET_LIB} log yaml ${RDMA_LIB} ${IBVERBS_LIB})
    if(USE_IBV_CQ_EVENT)
      target_compile_definitions(${NET_LIB} PUBLIC USE_INFINIBAND USE_IBV_CQ_EVENT)
    else()
      target_compile_definitions(${NET_LIB} PUBLIC USE_INFINIBAND)
    endif()
  else()
    message(FATAL_ERROR "InfiniBand libraries (rdmacm, ibverbs) not found")
  endif()
else()
  target_link_libraries(${NET_LIB} log yaml)
endif()

install(
  TARGETS ${NET_LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

option(PORTALS_LIB_DIR "Path to the Portals library" "")

find_library(
  PORTALS_LIB
  NAMES portals
  PATHS ${PORTALS_LIB_DIR})

if(PORTALS_LIB)
  message(STATUS "Portals library for client found at: ${PORTALS_LIB}")

  set(PORT_LIB "${PROJECT_NAME}_portals_lib")

  option(PORTALS_INCLUDE_DIR "Path to the Portals include directory" "")
  # Check if the include directory exists and is valid
  if(EXISTS "${PORTALS_INCLUDE_DIR}/portals4.h")
    message(
      STATUS
        "Found portals include directory for client: ${PORTALS_INCLUDE_DIR}")
  else()
    message(
      FATAL_ERROR
        "Could not find portals include directory for client in: ${PORTALS_INCLUDE_DIR}"
    )
  endif()

  # Use the provided option or infer from PORTALS_LIB_DIR
  if(NOT PORTALS_INCLUDE_DIR)
    # Try to infer the include directory based on PORTALS_LIB_DIR
    get_filename_component(PORTALS_LIB_DIR_INCLUDE ${PORTALS_LIB} DIRECTORY)
    set(PORTALS_INCLUDE_DIR "${PORTALS_LIB_DIR_INCLUDE}/../../portals/include")
    message(
      STATUS
        "Found portals include directory for client: ${PORTALS_INCLUDE_DIR}")
  endif()

  add_definitions(-DPARALLAX_PORTALS)

  set(PORT_LIB_SOURCE_FILES
      par_net/par_net_put.c
      par_net/par_net_open.c
      par_net/par_net_delete.c
      par_net/par_net_get.c
      par_net/par_net_close.c
      par_net/par_net_scan.c
      par_net/par_net_sync.c
      ../lib/api/parallax_client_lib.c
      ../lib/btree/key_splice.c
      ../lib/btree/set_options.c
      ../lib/btree/kv_pairs.c
      ../lib/common/common.c)

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set_source_files_properties(PORT_LIB_SOURCE_FILES
                                PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set_source_files_properties(
      PORT_LIB_SOURCE_FILES PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_RELEASE}")
  endif()

  add_library(${PORT_LIB} SHARED ${PORT_LIB_SOURCE_FILES})

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
               "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h")

  target_include_directories(
    ${PORT_LIB}
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include"
    PUBLIC "${PORTALS_INCLUDE_DIR}")
  include_directories("${PORTALS_INCLUDE_DIR}")

  target_link_libraries(${PORT_LIB} log yaml ${PORTALS_LIB})

  install(
    TARGETS ${PORT_LIB}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
else()
  message(
    WARNING "Portals library not found, stoping compilation with portalslib")
endif()
