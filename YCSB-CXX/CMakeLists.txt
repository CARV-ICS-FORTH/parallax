include(CheckCXXCompilerFlag)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${CMAKE_SOURCE_DIR}/lib)

set(NET_LIBRARY "")

if(PARALLAX_BUILD_TESTING)
  include_directories(BEFORE core db ${CMAKE_SOURCE_DIR}/lib/include)
  find_package(Boost REQUIRED)
  include_directories(${Boost_INCLUDE_DIRS})
  add_executable(ycsb-edb db/db_factory_parallax.cc core/core_workload.cc
                          driver/ycsbc.cc ../utilities/list.c)
  target_link_libraries(ycsb-edb PRIVATE "${PROJECT_NAME}" ${Boost_LIBRARIES}
                                         log Threads::Threads)

  add_executable(ycsb-tcp db/db_factory_parallax_tcp.cc core/core_workload.cc
                          driver/ycsbc.cc ../utilities/list.c)
  
  if(NET STREQUAL "portals")
    set(NET_LIBRARY "${PROJECT_NAME}_portals_lib")
  endif()
  
  target_link_libraries(
    ycsb-tcp PRIVATE "${PROJECT_NAME}_net_lib" ${Boost_LIBRARIES} log
                     Threads::Threads "${NET_LIBRARY}")
  
  check_cxx_compiler_flag("-Wno-deprecated-array-compare"
                          DEPRECATED_ARRAY_COMPARE)
  if(DEPRECATED_ARRAY_COMPARE)
    string(APPEND CMAKE_CXX_FLAGS " -Wno-deprecated-array-compare")
  endif()
  check_cxx_compiler_flag("-Wno-array-compare" ARRAY_COMPARE)
  if(ARRAY_COMPARE)
    string(APPEND CMAKE_CXX_FLAGS " -Wno-array-compare")
  endif()

  set(RECORD_COUNT 400000)
  set(OPERATION_COUNT 400000)

  add_parallax_test(
    NAME
    test_small
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    s)

  add_parallax_test(
    NAME
    test_medium
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    m)

  add_parallax_test(
    NAME
    test_large
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    l)

  add_parallax_test(
    NAME
    test_smalld
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    sd)

  add_parallax_test(
    NAME
    test_mediumd
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    md)

  add_parallax_test(
    NAME
    test_larged
    COMMAND
    run_test.sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    ld)
endif()
