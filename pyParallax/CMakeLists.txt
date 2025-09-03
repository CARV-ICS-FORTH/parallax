cmake_minimum_required(VERSION 3.14)
project(pyparallax LANGUAGES C)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

set(PYTHON_BUILD_DIR ${CMAKE_BINARY_DIR}/pyParallax)

add_library(pyparallax_shim MODULE ${CMAKE_SOURCE_DIR}/pyParallax/pyparallax_shim.c)

target_include_directories(pyparallax_shim PRIVATE
    ${Python3_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/lib/include/parallax
)

target_link_libraries(pyparallax_shim PRIVATE
    ${Python3_LIBRARIES}
    parallax
)

set_target_properties(pyparallax_shim PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${PYTHON_BUILD_DIR}
)

file(GLOB PY_FILES "${CMAKE_SOURCE_DIR}/pyParallax/*.py")
file(COPY ${PY_FILES} DESTINATION ${PYTHON_BUILD_DIR})

file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/README.md" DESTINATION ${PYTHON_BUILD_DIR})

file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/setup.py" DESTINATION ${CMAKE_BINARY_DIR})

