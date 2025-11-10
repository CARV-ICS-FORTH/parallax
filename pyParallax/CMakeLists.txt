cmake_minimum_required(VERSION 3.14)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

set(PYTHON_BUILD_DIR ${CMAKE_BINARY_DIR}/pyParallax)

add_library(pyparallax_shim MODULE ${CMAKE_SOURCE_DIR}/pyParallax/pyparallax_shim.c)

target_include_directories(pyparallax_shim PRIVATE
    ${Python3_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/lib/include 
    ${CMAKE_SOURCE_DIR}/net_interface
)

target_link_libraries(pyparallax_shim PRIVATE
    ${Python3_LIBRARIES}
    parallax_net_lib
    log
)

set_target_properties(pyparallax_shim PROPERTIES
  PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/../lib/include/parallax/parallax.h"  
  PREFIX ""
  SUFFIX ".so"
  LIBRARY_OUTPUT_DIRECTORY ${PYTHON_BUILD_DIR}
  BUILD_RPATH "${CMAKE_BINARY_DIR}/net_interface"
  INSTALL_RPATH "$ORIGIN"
)

file(GLOB PY_FILES "${CMAKE_SOURCE_DIR}/pyParallax/*.py")
file(COPY ${PY_FILES} DESTINATION ${PYTHON_BUILD_DIR})
file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/README.md" DESTINATION ${PYTHON_BUILD_DIR})
file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/setup.py" DESTINATION ${CMAKE_BINARY_DIR})

