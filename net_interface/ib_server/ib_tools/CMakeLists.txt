cmake_minimum_required(VERSION 3.26)
project(ib_tools C CXX)

find_library(PARALLAX_LIBRARY
    NAMES parallax
    HINTS ${CMAKE_INSTALL_PREFIX}/lib ${CMAKE_INSTALL_PREFIX}/lib64
    REQUIRED
)

find_library(PARALLAX_NET_LIBRARY
    NAMES parallax_net_lib
    HINTS ${CMAKE_INSTALL_PREFIX}/lib ${CMAKE_INSTALL_PREFIX}/lib64
    REQUIRED
)

find_path(PARALLAX_INCLUDE_DIR
    NAMES parallax.h
    HINTS ${CMAKE_INSTALL_PREFIX}/include /home1/public/nikosl/local/include
    REQUIRED
)

message(STATUS "Found Parallax main library: ${PARALLAX_LIBRARY}")
message(STATUS "Found Parallax IB library: ${PARALLAX_NET_LIBRARY}")
message(STATUS "Found Parallax includes: ${PARALLAX_INCLUDE_DIR}")

include_directories(${PARALLAX_INCLUDE_DIR})
link_directories(${MY_CUSTOM_LIB_DIR} ${CMAKE_INSTALL_PREFIX}/lib)

add_executable(ib_client_init ib_client_init.cpp)
add_executable(ib_simple_test ib_simple_test.c)

target_compile_options(ib_client_init PRIVATE $<$<CONFIG:Debug>:-g3 -O0 -ggdb>)
target_compile_options(ib_simple_test PRIVATE $<$<CONFIG:Debug>:-g3 -O0 -ggdb>)

target_link_libraries(ib_client_init ${PARALLAX_NET_LIBRARY} ${PARALLAX_LIBRARY} log)
target_link_libraries(ib_simple_test ${PARALLAX_NET_LIBRARY} ${PARALLAX_LIBRARY} log)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

install(TARGETS ib_client_init ib_simple_test
    RUNTIME DESTINATION bin
)
