set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(BEFORE core db ../lib)

add_executable(
  ycsb-edb db/db_factory_parallax.cc core/core_workload.cc
  driver/ycsbc.cc ../utilities/list.c
)
target_link_libraries(ycsb-edb "${PROJECT_NAME}" ${DEPENDENCIES})
target_compile_options(ycsb-edb PUBLIC "-Wno-array-compare")


if(BUILD_TESTING)
  find_program(BASH_PROGRAM bash)

  if(NOT BASH_PROGRAM)
    message(FATAL_ERROR "Bash executable not found")
  endif()

  set(RECORD_COUNT 400000)
  set(OPERATION_COUNT 400000)
  add_test(
    test_larged
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    ld
  )
  add_test(
    test_large
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    l
  )
  add_test(
    test_mediumd
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    md
  )
  add_test(
    test_medium
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    m
  )
  add_test(
    test_smalld
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    sd
  )
  add_test(
    test_small
    ${BASH_PROGRAM}
    ${CMAKE_CURRENT_SOURCE_DIR}/run-ycsb.sh
    ${FILEPATH}
    ${RECORD_COUNT}
    ${OPERATION_COUNT}
    s
  )
endif()
