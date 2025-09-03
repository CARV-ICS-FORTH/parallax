cmake_minimum_required(VERSION 3.14)
project(pyparallax LANGUAGES C)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Directory where Python package files will go
set(PYTHON_BUILD_DIR ${CMAKE_BINARY_DIR}/pyParallax)

# Build the C extension
add_library(pyparallax_shim MODULE ${CMAKE_SOURCE_DIR}/pyParallax/pyparallax_shim.c)

target_include_directories(pyparallax_shim PRIVATE
    ${Python3_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/lib/include/parallax
)

target_link_libraries(pyparallax_shim PRIVATE
    ${Python3_LIBRARIES}
    parallax
)

# Place the .so in build/pyParallax
set_target_properties(pyparallax_shim PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${PYTHON_BUILD_DIR}
)

# Copy Python files to build/pyParallax
file(GLOB PY_FILES "${CMAKE_SOURCE_DIR}/pyParallax/*.py")
file(COPY ${PY_FILES} DESTINATION ${PYTHON_BUILD_DIR})

# Copy README.md to build/pyParallax
file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/README.md" DESTINATION ${PYTHON_BUILD_DIR})

# Copy setup.py to build/ (not into pyParallax)
file(COPY "${CMAKE_SOURCE_DIR}/pyParallax/setup.py" DESTINATION ${CMAKE_BINARY_DIR})

