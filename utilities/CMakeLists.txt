# File: kreon/CMakeLists.txt Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set_source_files_properties(spin_loop.c PROPERTIES COMPILE_FLAGS "-O0")

set_source_files_properties(list.c PROPERTIES COMPILE_FLAGS "-O3")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lrt -lm -pthread -lnuma")

add_library(utilities STATIC list.c)
