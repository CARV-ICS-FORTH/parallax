set(SURROGATE_TEST_SOURCES
    surr_allocator.c
    surr_btree.c
    surr_dynamic_leaf.c
    surr_gc.c
    surr_segment_allocator.c
    surr_min_max_heap.c
    surr_scanner.c
    surr_stack.c
    main.c)

add_executable(SurrogateTUsTest ${SURROGATE_TEST_SOURCES})
target_link_libraries(SurrogateTUsTest "${PROJECT_NAME}")
add_test(NAME SurrogateTUsTest COMMAND $<TARGET_FILE:SurrogateTUsTest>)
