cmake_minimum_required(VERSION 3.10)

# Add executable for the first test
add_executable(initial_test main.cpp)

# Link against GTest
# gtest_main includes GTest::gtest and GTest::gtest_main
# GTest::gtest_main provides a default main() function for tests
target_link_libraries(initial_test PRIVATE GTest::gtest_main)

# Include GTest module for test discovery functionality
# This should ideally be done once.
include(GoogleTest)

gtest_discover_tests(initial_test)

# Ensure tests can find project headers
target_include_directories(initial_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# If tests need to link against project libraries (e.g., netflow_switching_lib)
# you would add them here. For the initial test, it might not be necessary
# if it's testing something very basic or standalone.
# Example: target_link_libraries(initial_test PRIVATE netflow_switching_lib)

# Add executable for packet tests
add_executable(packet_test packet_test.cpp)

# Link against GTest
target_link_libraries(packet_test PRIVATE GTest::gtest_main)

# Discover tests for the new executable
gtest_discover_tests(packet_test)

# Ensure tests can find project headers
target_include_directories(packet_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for ForwardingDatabase tests
add_executable(fdb_test forwarding_database_test.cpp)

# Link against GTest
target_link_libraries(fdb_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
# as ForwardingDatabase is a compiled component.
target_link_libraries(fdb_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(fdb_test)

# Ensure tests can find project headers
target_include_directories(fdb_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for VlanManager tests
add_executable(vlan_manager_test vlan_manager_test.cpp)

# Link against GTest
target_link_libraries(vlan_manager_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
# as VlanManager is a compiled component.
target_link_libraries(vlan_manager_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(vlan_manager_test)

# Ensure tests can find project headers
target_include_directories(vlan_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for InterfaceManager tests
add_executable(interface_manager_test interface_manager_test.cpp)

# Link against GTest
target_link_libraries(interface_manager_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
target_link_libraries(interface_manager_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(interface_manager_test)

# Ensure tests can find project headers
target_include_directories(interface_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for PacketClassifier tests
add_executable(packet_classifier_test packet_classifier_test.cpp)

# Link against GTest
target_link_libraries(packet_classifier_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
target_link_libraries(packet_classifier_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(packet_classifier_test)

# Ensure tests can find project headers
target_include_directories(packet_classifier_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for LacpManager tests
add_executable(lacp_manager_test lacp_manager_test.cpp)

# Link against GTest
target_link_libraries(lacp_manager_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
target_link_libraries(lacp_manager_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(lacp_manager_test)

# Ensure tests can find project headers
target_include_directories(lacp_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for ConfigManager tests
add_executable(config_manager_test config_manager_test.cpp)

# Link against GTest
target_link_libraries(config_manager_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
# ConfigManager might be header-only or part of the lib, linking defensively.
target_link_libraries(config_manager_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(config_manager_test)

# Ensure tests can find project headers
target_include_directories(config_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)
