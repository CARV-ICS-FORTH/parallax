# File: CMakeLists.txt
# Author: Michalis Vardoulakis <mvard@ics.forth.gr>

cmake_minimum_required(VERSION 3.0.2)
include(ExternalProject)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE "Debug")

ExternalProject_Add(uthash
  GIT_REPOSITORY https://github.com/troydhanson/uthash.git
  PREFIX external-deps
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
)

include_directories(
  /usr/include/zookeeper
)

# Compiler configuration
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_C_FLAGS_RELEASE "-std=gnu99 -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_RELEASE} -g")
set(CMAKE_CXX_FLAGS_RELEASE "-std=gnu++11 -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_RELEASE} -g")

add_subdirectory(kreon_rdma build/tests/kreon_rdma)
add_subdirectory(kreon_lib build/kreon_lib)
add_subdirectory(kreon_server build/kreon_server)
add_subdirectory(utilities build/utilities)
add_subdirectory(tests build/tests)
