# File: TuRDMA/CMakeLists.txt
# Author: Michalis Vardoulakis <mvard@ics.forth.gr>


#add_library(turdma STATIC memory_regions.c tu_rdma.c ../kreon/allocator/list.c)
add_library(kreon_rdma_lib STATIC memory_region_pool.c rdma.c ../utilities/queue.c ../utilities/simple_concurrent_list.c ../utilities/spin_loop.c ../utilities/circular_buffer.c ../utilities/list.c)

#add_executable(test_rdma test_rdma.c)
#set_target_properties(test_rdma PROPERTIES
  #LINK_FLAGS "-libverbs -pthread -D_GNU_SOURCE"
#)
#target_link_libraries(test_rdma turdma)
