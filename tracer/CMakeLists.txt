set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(BUILD_TESTING)
  set(LIB_TRACER_FILES tracer.c)

  set_source_files_properties(${LIB_TRACER_FILES} COMPILE_FLAGS "-O3")

  add_executable(tracer tracer.c ../tests/arg_parser.c)
  target_link_libraries(tracer "${PROJECT_NAME}")

  add_parallax_test(NAME tracer COMMAND run_test.sh tracer
                    --tracefile=${CMAKE_CURRENT_SOURCE_DIR}/dummy_tracefile.txt)

endif()
