add_executable(test_timer test_timer.c)
target_link_libraries(test_timer PRIVATE pqc_framework)
add_test(NAME timer COMMAND test_timer)
