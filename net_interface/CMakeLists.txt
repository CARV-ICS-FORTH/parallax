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

target_link_libraries(${NET_LIB} log yaml)

install(
  TARGETS ${NET_LIB}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

option(PORTALS_LIB_DIR "Path to the Portals library" "")

find_library(PORTALS_LIB NAMES portals
    PATHS ${PORTALS_LIB_DIR}
)

if(PORTALS_LIB)
  message(STATUS "Portals library found at: ${PORTALS_LIB}")

  set(PORT_LIB "${PROJECT_NAME}_portals_lib")
  
  # Check if the include directory exists and is valid
  if(EXISTS "${PORTALS_INCLUDE_DIR}/portals4.h")
      message(STATUS "Found portals4.h at: ${PORTALS_INCLUDE_DIR}")
  else()
      message(FATAL_ERROR "Could not find portals4.h in ${PORTALS_INCLUDE_DIR}")
  endif()

  option(PORTALS_INCLUDE_DIR "Path to the Portals include directory" "")

  # Use the provided option or infer from PORTALS_LIB_DIR
  if(NOT PORTALS_INCLUDE_DIR)
      # Try to infer the include directory based on PORTALS_LIB_DIR
      get_filename_component(PORTALS_LIB_DIR_INCLUDE ${PORTALS_LIB} DIRECTORY)
      set(PORTALS_INCLUDE_DIR "${PORTALS_LIB_DIR_INCLUDE}/../../portals/include")
  endif()

  message(STATUS "Portals include directory: ${PORTALS_INCLUDE_DIR}")
  
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

  add_library(${PORT_LIB} SHARED ${PORT_LIB_SOURCE_FILES})

  set_target_properties(
    ${PORT_LIB}
    PROPERTIES PUBLIC_HEADER
             "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h")

  target_include_directories(${PORT_LIB}
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include"
                           PUBLIC "${PORTALS_INCLUDE_DIR}")

  target_link_libraries(${PORT_LIB} log yaml ${PORTALS_LIB})

  install(
    TARGETS ${PORT_LIB}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
else()
  message(WARNING "Portals library not found, stoping compilation with portalslib")
endif()
