# File: kreon/CMakeLists.txt
# Author: Michalis Vardoulakis <mvard@ics.forth.gr>

set_source_files_properties(allocator/list.c PROPERTIES
  COMPILE_FLAGS "-O3"
)
set_source_files_properties(allocator/recovery.c PROPERTIES
  COMPILE_FLAGS "-O3 -DKREONR"
)
set_source_files_properties(allocator/allocator.c PROPERTIES
  COMPILE_FLAGS "-O3 -DKREONR"
)
set_source_files_properties(btree/btree.c PROPERTIES
  COMPILE_FLAGS "-O3 -DKREONR"
)
set_source_files_properties(btree/replica.c PROPERTIES
  COMPILE_FLAGS "-O0 -ggdb3 -g -DKREONR"
)
set_source_files_properties(scanner/stack.c PROPERTIES
  COMPILE_FLAGS "-O3"
)
set_source_files_properties(scanner/min_max_heap.c PROPERTIES
  COMPILE_FLAGS "-O3"
)
set_source_files_properties(scanner/scanner.c PROPERTIES
  COMPILE_FLAGS "-O3"
)
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O3")

set(CMAKE_EXE_LINKER_FLAGS "-lrt -lm -pthread -lnuma")


# Kreon with replication enabled
add_library(kreon_server_lib  STATIC  allocator/recovery.c
  ../utilities/spin_loop.c allocator/allocator.c btree/btree.c
  btree/replica.c ../utilities/stack.c ../utilities/min_max_heap.c
  scanner/scanner.c ../utilities/list.c
)


set_target_properties(kreon_server_lib PROPERTIES COMPILE_DEFINITIONS "KREONR")

#Kreon with replication disabled
add_library(kreon_local STATIC  allocator/recovery.c
  ../utilities/spin_loop.c allocator/allocator.c btree/btree.c
  btree/replica.c ../utilities/stack.c ../utilities/min_max_heap.c
  scanner/scanner.c
)


set_source_files_properties(allocator/spin_loop.c PROPERTIES
  COMPILE_FLAGS "-O0"
)
set_source_files_properties(allocator/list.c PROPERTIES
  COMPILE_FLAGS "-O3"
)
set_source_files_properties(allocator/allocator.c PROPERTIES
  COMPILE_FLAGS "-O3"
)

# mkfs for kreon volumes
add_executable(mkfs.eutropia allocator/mkfs_Eutropia.c ../utilities/spin_loop.c
  allocator/allocator.c ../utilities/list.c 
)


