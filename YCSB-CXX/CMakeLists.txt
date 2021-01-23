# File: YCSB-CXX/CMakeLists.txt Author: Michalis Vardoulakis
# <mvard@ics.forth.gr>

include_directories(BEFORE core db ../lib)

add_executable(ycsb-edb db/db_factory_eutropiadb.cc core/core_workload.cc
                        driver/ycsbc.cc ../utilities/list.c)
target_link_libraries(ycsb-edb ${PROJECT_NAME} ${DEPENDENCIES})
