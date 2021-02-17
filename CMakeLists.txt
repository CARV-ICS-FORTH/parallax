include(cmake_utils/PreventInSouceBuilds.cmake.in)
cmake_minimum_required(VERSION 3.11.0 FATAL_ERROR)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
project(
  parallax
  VERSION 1.0
  LANGUAGES C CXX)

option(BUILD_SHARED_LIBS
       "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" OFF)

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

include(FetchContent)
include(CPack)
include(GNUInstallDirs)
include(cmake_utils/mkfs.cmake.in)
include(cmake_utils/ycsb.cmake.in)
include(cmake_utils/tests.cmake.in)
include(cmake_utils/cmakeconfig.cmake.in)
configure_file(config.h.in config.h @ONLY)

set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
  log
  GIT_REPOSITORY https://github.com/innerout/log.c.git
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  libmba
  GIT_REPOSITORY https://github.com/innerout/libmba.git
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  yaml
  GIT_REPOSITORY https://github.com/yaml/libyaml
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  uthash
  GIT_REPOSITORY https://github.com/troydhanson/uthash
  GIT_PROGRESS TRUE)

FetchContent_GetProperties(log)
FetchContent_GetProperties(libmba)
FetchContent_GetProperties(yaml)
FetchContent_GetProperties(uthash)

if(NOT log_POPULATED)
  FetchContent_Populate(log)
  add_subdirectory(${log_SOURCE_DIR} ${log_BINARY_DIR})
  include_directories(${log_SOURCE_DIR}/include)
  FetchContent_MakeAvailable(log)
endif()

if(NOT libmba_POPULATED)
  FetchContent_Populate(libmba)
  add_subdirectory(${libmba_SOURCE_DIR} ${libmba_BINARY_DIR})
  FetchContent_MakeAvailable(libmba)
endif()

if(NOT yaml_POPULATED)
  FetchContent_Populate(yaml)
  add_subdirectory(${yaml_SOURCE_DIR} ${yaml_BINARY_DIR})
  FetchContent_MakeAvailable(yaml)
endif()

# Do not add uthash in the DEPENDENCIES variable. Uthash is a special case
# because it is a header only library & does not support cmake.
if(NOT uthash_POPULATED)
  FetchContent_Populate(uthash)
  include_directories(${uthash_SOURCE_DIR}/src)
  FetchContent_MakeAvailable(uthash)
endif()

set(DEPENDENCIES log libmba yaml)

include_directories(${CMAKE_BINARY_DIR})

set(CMAKE_C_FLAGS
    "-std=gnu11 -Wstrict-prototypes -Wall -Wextra -fPIC -fno-omit-frame-pointer -Wunused -Wuninitialized -Wshadow -Wnull-dereference -Werror ${CMAKE_C_FLAGS}"
)
set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -Og ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_RELEASE
    "${CMAKE_C_FLAGS_RELEASE} -flto -funit-at-a-time -fprefetch-loop-arrays -fpeel-loops -O2 -finline-functions -DNDEBUG"
)
set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} -std=gnu++11 -Wall -Werror")

set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed -lrt -lm -pthread -lnuma -lutil"
)

add_subdirectory(lib)
add_subdirectory(YCSB-CXX)
add_subdirectory(utilities)
add_subdirectory(tests)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_VENDOR "FORTH-ICS")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "${PROJECT_NAME} is a high-speed and high-efficiency key-value store.")
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_PACKAGE_LICENSE "ASL v2.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Databases")
set(CPACK_RPM_PACKAGE_REQUIRES "numactl-libs >= 2")
set(CPACK_RPM_PACKAGE_DESCRIPTION
    "${PROJECT_NAME} is a high-speed and high-efficiency key-value store.")
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}"
)

if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_utils/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)

  add_custom_target(
    uninstall COMMAND ${CMAKE_COMMAND} -P
                      ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
