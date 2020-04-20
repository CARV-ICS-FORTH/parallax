# File: CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

cmake_minimum_required(VERSION 3.11.0)
include(FetchContent)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
project(kreon VERSION 1.0)

# Set a default build type if none was specified
set(default_build_type "Release")
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
  set(default_build_type "Debug")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(
    STATUS
      "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE
      "${default_build_type}"
      CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                               "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)
include(cmake_utils/mkfs.cmake.in)
include(cmake_utils/ycsb.cmake.in)

FetchContent_Declare(
  uthash # Recommendation: Stick close to the original name.
  GIT_REPOSITORY https://github.com/troydhanson/uthash.git
  SOURCE_DIR
  external-deps/src/uthash # (Relative) path within in the build directory.
)

FetchContent_Declare(log # Recommendation: Stick close to the original name.
                     GIT_REPOSITORY https://github.com/innerout/log.c.git)

FetchContent_GetProperties(uthash)
FetchContent_GetProperties(log)

if(NOT uthash_POPULATED)
  FetchContent_Populate(uthash)
  FetchContent_MakeAvailable(uthash)
endif()

if(NOT log_POPULATED)
  FetchContent_Populate(log)
  add_subdirectory(${log_SOURCE_DIR} ${log_BINARY_DIR})
  include_directories(${log_SOURCE_DIR}/include)
  FetchContent_MakeAvailable(log)
endif()

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
  if(NOT TARGET uninstall)
    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/cmake_utils/cmake_uninstall.cmake.in"
      "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)

    add_custom_target(
      uninstall COMMAND ${CMAKE_COMMAND} -P
                        ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
  endif()

endif()
