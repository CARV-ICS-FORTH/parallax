include(cmake_utils/PreventInSouceBuilds.cmake.in)
cmake_minimum_required(VERSION 3.11.0 FATAL_ERROR)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(
  parallax
  VERSION 1.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS
       "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" OFF)
option(DISABLE_LOGGING
       "Disable all logging from parallax excluding kv_format.parallax output."
       OFF)
# Set a default build type if none was specified
set(default_build_type "Release")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  set(default_build_type "Debug")
endif()

# Parallax is a dependency
if(NOT (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR}))
  option(BUILD_TESTING "" OFF)
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

if(DISABLE_LOGGING)
  add_definitions(-DDISABLE_LOGGING)
endif()

include(FetchContent)
include(CTest)
include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(cmake_utils/mkfs.cmake.in)
include(cmake_utils/ycsb.cmake.in)
include(cmake_utils/tests.cmake.in)
include(cmake_utils/tracer.cmake.in)

if(RUN_IWYU STREQUAL "ON")
  file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/scripts/CI/check-iwyu-output.py
       DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()

set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
  log
  GIT_REPOSITORY https://github.com/innerout/log.c.git
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  yaml
  GIT_REPOSITORY https://github.com/yaml/libyaml
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  uthash
  GIT_REPOSITORY https://github.com/troydhanson/uthash
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  cmake-scripts
  GIT_REPOSITORY https://github.com/StableCoder/cmake-scripts.git
  GIT_TAG main
  GIT_PROGRESS TRUE)

FetchContent_Declare(
  libbloom
  GIT_REPOSITORY https://github.com/innerout/libbloom
  GIT_TAG cmake)

FetchContent_GetProperties(log)
FetchContent_GetProperties(yaml)
FetchContent_GetProperties(uthash)
FetchContent_GetProperties(cmake-scripts)
FetchContent_GetProperties(libbloom)

if(NOT log_POPULATED)
  FetchContent_Populate(log)
  add_subdirectory(${log_SOURCE_DIR} ${log_BINARY_DIR})
  FetchContent_MakeAvailable(log)
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

if(NOT cmake-scripts_POPULATED)
  FetchContent_Populate(cmake-scripts)
  FetchContent_MakeAvailable(cmake-scripts)
  include(${cmake-scripts_SOURCE_DIR}/sanitizers.cmake)
endif()

if(NOT libbloom_POPULATED)
  FetchContent_Populate(libbloom)
  add_subdirectory(${libbloom_SOURCE_DIR} ${libbloom_BINARY_DIR})
  include_directories(${libbloom_SOURCE_DIR}/include)
  FetchContent_MakeAvailable(libbloom)
endif()

set(DEPENDENCIES log yaml libbloom)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utilities)

if(TREAT_WARNINGS_AS_ERRORS)
  set(CMAKE_C_FLAGS " -Werror ${CMAKE_C_FLAGS}")
  set(CMAKE_CXX_FLAGS " -Werror ${CMAKE_CXX_FLAGS}")
endif()

string(
  APPEND
  CMAKE_C_FLAGS
  " -Wstrict-prototypes -Wall -Wextra -fno-omit-frame-pointer -Wunused -Wuninitialized"
)
string(
  APPEND
  CMAKE_C_FLAGS
  " -Wimplicit-function-declaration -Wshadow -pedantic -pedantic-errors -Wmisleading-indentation -pipe"
)
string(APPEND CMAKE_CXX_FLAGS " -pipe")
include(cmake_utils/check-compiler-flags.cmake.in)

set(DEVICE_PATH $ENV{NVME0})
set(CI_JOB_ID $ENV{CI_JOB_ID})
set(FILEPATH "${DEVICE_PATH}/${CI_JOB_ID}/kv_store.dat")

# if(NOT (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_ID
# STREQUAL "Clang")) string(APPEND CMAKE_C_FLAGS " -flto") string(APPEND
# CMAKE_CXX_FLAGS " -flto") endif()

set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -Og -gz ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_RELEASE
    "${CMAKE_C_FLAGS_RELEASE} -funit-at-a-time -O2 -finline-functions -DNDEBUG")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=gnu++11 -Wall")

set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed -lrt -lm -pthread -lnuma -lutil"
)

add_subdirectory(lib)
add_subdirectory(YCSB-CXX)
add_subdirectory(utilities)
add_subdirectory(tests)
add_subdirectory(tracer)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_VENDOR "FORTH-ICS")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "${PROJECT_NAME} is a high-speed and high-efficiency key-value store.")
set(CPACK_PACKAGE_CONTACT
    "Giorgos Saloustros <gesalous@ics.forth.gr, Giorgos Xanthakis <gxanth@ics.forth.gr>, Giorgos Stylianakis <geostyl@ics.forth.gr>"
)

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

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libnuma-dev (>= 2.0.12)")

if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_utils/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)

  add_custom_target(
    uninstall COMMAND ${CMAKE_COMMAND} -P
                      ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# This should be left at the end of the CMakeLists otherwise the generation of
# RPM and DEB packages will not work.
include(CPack)
