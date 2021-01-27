include_directories(BEFORE core db ../lib)

add_executable(ycsb-edb db/db_factory_parallax.cc core/core_workload.cc
                        driver/ycsbc.cc ../utilities/list.c)
target_link_libraries(ycsb-edb ${PROJECT_NAME} ${DEPENDENCIES})
