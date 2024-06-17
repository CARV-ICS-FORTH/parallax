include(cmake_utils/PreventInSouceBuilds.cmake.in)
cmake_minimum_required(VERSION 3.11.0 FATAL_ERROR)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(
  parallax
  VERSION 1.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT DEFINED ALIGNMENT_SIZE)
  set(ALIGNMENT_SIZE "512UL") # Set without UL suffix if not defined
else()
  # Append UL suffix if not already present
  string(REGEX MATCH "[0-9]+UL" HAS_UL_SUFFIX "${ALIGNMENT_SIZE}")
  if(NOT HAS_UL_SUFFIX)
    set(ALIGNMENT_SIZE "${ALIGNMENT_SIZE}UL")
  endif()
endif()
add_definitions(-DALIGNMENT_SIZE=${ALIGNMENT_SIZE})

if(NOT DEFINED SEGMENT_SIZE)
  set(SEGMENT_SIZE "2097152UL") # Set without UL suffix if not defined
else()
  # Append UL suffix if not already present
  string(REGEX MATCH "[0-9]+UL" HAS_UL_SUFFIX "${SEGMENT_SIZE}")
  if(NOT HAS_UL_SUFFIX)
    set(SEGMENT_SIZE "${SEGMENT_SIZE}UL")
  endif()
endif()
add_definitions(-DSEGMENT_SIZE=${SEGMENT_SIZE})

option(BUILD_SHARED_LIBS
       "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" OFF)
option(DISABLE_LOGGING
       "Disable all logging from parallax excluding kv_format.parallax output."
       OFF)
option(TEBIS_FORMAT "BUild Parallax using Tebis-format" OFF)
option(PARALLAX_BUILD_TESTING "" ON)

if(NOT (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR}))
  set(PARALLAX_BUILD_TESTING OFF)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to Release as none was specified.")
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                               "MinSizeRel" "RelWithDebInfo")
endif()

if(NOT (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR}))
  set(CMAKE_BUILD_TYPE Release)
  add_definitions(-DDISABLE_LOGGING)
endif()

message(
  STATUS
    "build type is '${default_build_type}' and cmake build type is '${CMAKE_BUILD_TYPE}'."
)

if(DISABLE_LOGGING)
  add_definitions(-DDISABLE_LOGGING)
endif()

if(TEBIS_FORMAT)
  add_definitions(-DTEBIS_FORMAT)
endif()

include(FetchContent)
include(CTest)
include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(cmake_utils/mkfs.cmake.in)
include(cmake_utils/ycsb.cmake.in)
include(cmake_utils/tests.cmake.in)
include(cmake_utils/tracer.cmake.in)

set(FILENAME_NUMBER
    "0"
    CACHE INTERNAL
          "Internal cmake variable to generate unique filenames for tests")
include(cmake_utils/generate_test_names.cmake.in)

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
  GIT_REPOSITORY https://github.com/gesalous/libbloom
  GIT_TAG additions_in_public_api)

# add Minos for memory guards
FetchContent_Declare(
  minos # Recommendation: Stick close to the original name.
  GIT_REPOSITORY https://github.com/CARV-ICS-FORTH/minos
  GIT_TAG parallax_fixes)

FetchContent_GetProperties(minos)
FetchContent_GetProperties(log)
FetchContent_GetProperties(yaml)
FetchContent_GetProperties(uthash)
FetchContent_GetProperties(cmake-scripts)
FetchContent_GetProperties(libbloom)

if(NOT cmake-scripts_POPULATED)
  FetchContent_Populate(cmake-scripts)
  FetchContent_MakeAvailable(cmake-scripts)
  include(${cmake-scripts_SOURCE_DIR}/sanitizers.cmake)
endif()

if(NOT log_POPULATED)
  FetchContent_Populate(log)
  add_subdirectory(${log_SOURCE_DIR} ${log_BINARY_DIR})
  FetchContent_MakeAvailable(log)
endif()

if(NOT minos_POPULATED)
  FetchContent_Populate(minos)
  add_subdirectory(${minos_SOURCE_DIR} ${minos_BINARY_DIR})
  include_directories(${minos_SOURCE_DIR}/include)
  FetchContent_MakeAvailable(minos)
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

if(NOT libbloom_POPULATED)
  FetchContent_Populate(libbloom)
  add_subdirectory(${libbloom_SOURCE_DIR} ${libbloom_BINARY_DIR})
  include_directories(${libbloom_SOURCE_DIR}/include)
  FetchContent_MakeAvailable(libbloom)
endif()

set(DEPENDENCIES log yaml libbloom minos)

# Find pthread library
find_package(Threads REQUIRED)
list(APPEND DEPENDENCIES "${CMAKE_THREAD_LIBS_INIT}")

find_library(LIBRT rt REQUIRED)
list(APPEND DEPENDENCIES "${LIBRT}")

find_library(LIBM m REQUIRED)
list(APPEND DEPENDENCIES "${LIBM}")

find_library(LIBNUMA numa REQUIRED)
list(APPEND DEPENDENCIES "${LIBNUMA}")

find_library(LIBUTIL util REQUIRED)
list(APPEND DEPENDENCIES "${LIBUTIL}")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions(-DLOG_LEVEL_RELEASE)
endif()

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utilities)

add_compile_definitions(
  DB_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/options.yml")

if(TREAT_WARNINGS_AS_ERRORS)
  string(APPEND CMAKE_C_FLAGS " -Werror")
  string(APPEND CMAKE_CXX_FLAGS " -Werror")
endif()

string(
  APPEND
  CMAKE_C_FLAGS
  " -Wstrict-prototypes -Wall -Wextra -fno-omit-frame-pointer -Wunused -Wuninitialized -pg"
)
string(
  APPEND
  CMAKE_C_FLAGS
  " -Wimplicit-function-declaration -Wshadow -pedantic -pedantic-errors -Wmisleading-indentation -pipe"
)
string(APPEND CMAKE_CXX_FLAGS " -pipe")
include(cmake_utils/check-compiler-flags.cmake.in)

if(ENABLE_FLTO)
  message("FLTO is enabled!")
  string(APPEND CMAKE_C_FLAGS " -flto=auto")
  string(APPEND CMAKE_CXX_FLAGS " -flto=auto")
  if(NOT (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_ID
                                                   STREQUAL "Clang"))
    set(CMAKE_AR "gcc-ar")
  endif()
endif()

string(APPEND CMAKE_C_FLAGS_DEBUG " -ggdb3 -Og -gz")
string(APPEND CMAKE_C_FLAGS_RELEASE " -O2 -finline-functions -DNDEBUG")
string(APPEND CMAKE_CXX_FLAGS_RELEASE " -std=gnu++11 -Wall")
# string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,--no-as-needed -lrt -lm -pthread
# -lnuma -lutil")
string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,--no-as-needed")

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
    parallax-uninstall
    COMMAND ${CMAKE_COMMAND} -P
            ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# This should be left at the end of the CMakeLists otherwise the generation of
# RPM and DEB packages will not work.
include(CPack)
