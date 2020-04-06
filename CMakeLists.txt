# File: CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

cmake_minimum_required(VERSION 3.11.0)
include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(kreon VERSION 1.0)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  message("Debug build")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  message("Release build")
else()
  message(WARNING "No build type specified defaults to Debug build!")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

file(GLOB_RECURSE ALL_C_SOURCE_FILES ${CMAKE_SOURCE_DIR}/kreon/*.c
     ${CMAKE_SOURCE_DIR}/kreon/*.h ${CMAKE_SOURCE_DIR}/tests/*.c
     ${CMAKE_SOURCE_DIR}/tests/*.h)

file(COPY ${CMAKE_SOURCE_DIR}/scripts/mkfs.eutropia.single.sh
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/YCSB-CXX/)

file(COPY ${CMAKE_SOURCE_DIR}/scripts/mkfs.eutropia.single.sh
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/tests/)

file(COPY ${CMAKE_SOURCE_DIR}/YCSB-CXX/workloads
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/YCSB-CXX/)

file(COPY ${CMAKE_SOURCE_DIR}/YCSB-CXX/execution_plan.txt
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/YCSB-CXX/)

find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
  add_custom_target(format COMMAND clang-format -i ${ALL_C_SOURCE_FILES})
else()
  message("Clang-format not installed!")
endif()

FetchContent_Populate(
  uthash # Recommendation: Stick close to the original name.
  GIT_REPOSITORY https://github.com/troydhanson/uthash.git
  SOURCE_DIR external-deps/src/uthash # (Relative) path within in the build
                                      # directory.
)

FetchContent_Populate(
  log # Recommendation: Stick close to the original name.
  GIT_REPOSITORY https://github.com/rxi/log.c.git
  SOURCE_DIR external-deps/log # (Relative) path within in the build directory.
)

set(Zookeeper_LIB_PATHS /usr/local/lib /opt/local/lib /usr/lib/x86_64-linux-gnu)
find_path(Zookeeper_INCLUDE_DIR zookeeper.h /usr/local/include /usr/include
          /usr/include/zookeeper)
find_library(
  Zookeeper_LIBRARY
  NAMES zookeeper_mt
  PATHS ${Zookeeper_LIB_PATHS})

if(NOT Zookeeper_INCLUDE_DIR)
  message("Could not find zookeeper header")
else()
  message("Zookeeper headers at ${Zookeeper_INCLUDE_DIR}")
  include_directories(${Zookeeper_INCLUDE_DIR})
endif()

if(NOT Zookeeper_LIBRARY)
  message("Could not find zookeeper lib needs >= 3.4.5")
else()
  message("Zookeeper headers at ${Zookeeper_LIBRARY}")
endif()

# Paths set(ZK_C_LIB "/home1/public/mvard/zookeeper_c")
include(CMakeconfig.txt)
configure_file(config.h.in config.h @ONLY)

include_directories(${CMAKE_BINARY_DIR}/external-deps/log/src/)
# Compiler configuration
if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER "gcc")
endif()

if(NOT CMAKE_CXX_COMPILER)
  set(CMAKE_CXX_COMPILER "g++")
endif()

include_directories(${CMAKE_BINARY_DIR})
set(CMAKE_C_FLAGS_RELEASE "-std=gnu99 -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_RELEASE} -g ")
set(CMAKE_CXX_FLAGS_RELEASE "-std=gnu++11 -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_RELEASE} -g")

if(Zookeeper_LIBRARY)
  add_subdirectory(kreon_rdma)
endif()
add_subdirectory(kreon_lib)
if(Zookeeper_LIBRARY)
  add_subdirectory(kreon_server)
endif()
add_subdirectory(YCSB-CXX)
add_subdirectory(utilities)
add_subdirectory(tests)
if(Zookeeper_LIBRARY)
  add_subdirectory(microbenchmarks)
endif()

if(KREON_BUILD_CPACK
   AND Zookeeper_INCLUDE_DIR
   AND Zookeeper_LIBRARY)
  set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
  set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
  set(CPACK_PACKAGE_RELEASE 1)
  set(CPACK_PACKAGE_VENDOR "FORTH-ICS")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
      "RDMA-based distributed key-value store")
  set(CPACK_GENERATOR "RPM")
  set(CPACK_RPM_PACKAGE_LICENSE "ASL v2.0")
  set(CPACK_RPM_PACKAGE_GROUP "Applications/Databases")
  set(CPACK_RPM_PACKAGE_REQUIRES
      "numactl-libs >= 2, libibverbs, librdmacm, glibc, libgcc, libnl3, zookeeper-native >= 3"
  )
  set(CPACK_RPM_PACKAGE_DESCRIPTION
      "Kreon is a high-speed and high-efficiency distributed key-value store functioning on top of an RDMA-capable network."
  )
  set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
  set(CPACK_PACKAGE_FILE_NAME
      "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}"
  )
  include(CPack)
endif()
