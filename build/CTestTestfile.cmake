# CMake generated Testfile for
# Source directory: /app
# Build directory: /app/build
#
# This file includes the relevant testing commands required for
# testing this directory and lists subdirectories to be tested as well.
add_test(ExampleTest1 "/app/build/phase1_packet_usage")
set_tests_properties(ExampleTest1 PROPERTIES  _BACKTRACE_TRIPLES "/app/CMakeLists.txt;63;add_test;/app/CMakeLists.txt;0;")
add_test(ExampleTest2 "/app/build/phase2_l2_parsing")
set_tests_properties(ExampleTest2 PROPERTIES  _BACKTRACE_TRIPLES "/app/CMakeLists.txt;64;add_test;/app/CMakeLists.txt;0;")
add_test(ExampleTest3 "/app/build/phase3_fdb_usage")
set_tests_properties(ExampleTest3 PROPERTIES  _BACKTRACE_TRIPLES "/app/CMakeLists.txt;65;add_test;/app/CMakeLists.txt;0;")
add_test(ExampleTest4 "/app/build/phase4_interface_vlan_config")
set_tests_properties(ExampleTest4 PROPERTIES  _BACKTRACE_TRIPLES "/app/CMakeLists.txt;66;add_test;/app/CMakeLists.txt;0;")
subdirs("src")
