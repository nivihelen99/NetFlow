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

# Add executable for QosManager tests
add_executable(qos_manager_test qos_manager_test.cpp)

# Link against GTest
target_link_libraries(qos_manager_test PRIVATE GTest::gtest_main)

# Link against the NetFlow library (netflow_switching_lib)
target_link_libraries(qos_manager_test PRIVATE netflow_switching_lib)

# Discover tests for the new executable
gtest_discover_tests(qos_manager_test)

# Ensure tests can find project headers
target_include_directories(qos_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for AclManager tests
add_executable(acl_manager_test acl_manager_test.cpp)

# Link against GTest and NetFlow library
target_link_libraries(acl_manager_test PRIVATE netflow_switching_lib GTest::gtest_main)

# Discover tests for the new executable
gtest_discover_tests(acl_manager_test)

# Ensure tests can find project headers
target_include_directories(acl_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for AclIntegration tests
add_executable(acl_integration_test acl_integration_test.cpp)
target_link_libraries(acl_integration_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(acl_integration_test)
target_include_directories(acl_integration_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for BufferPool tests
add_executable(buffer_pool_test buffer_pool_test.cpp)
# BufferPool is header-only but uses PacketBuffer from the library.
# No other specific source files from netflow_switching_lib are directly compiled for buffer_pool_test itself,
# but linking netflow_switching_lib makes PacketBuffer definition available if it's not header-only.
# PacketBuffer.hpp seems to be header-only based on its nature.
# If PacketBuffer is indeed header-only and has no .cpp, netflow_switching_lib might not be strictly needed here,
# but it's safer to include if PacketBuffer could have associated compiled code or dependencies.
# Let's assume PacketBuffer is effectively header-only or its definitions are available through headers.
# GTest::gtest_main is needed.
target_link_libraries(buffer_pool_test PRIVATE netflow_switching_lib GTest::gtest_main)
# Add netflow_switching_lib if any underlying types used by BufferPool/PacketBuffer are compiled in it.
# PacketBuffer is used by Packet, which is used everywhere, so netflow_switching_lib is usually linked by other tests.
# However, if BufferPool and PacketBuffer are purely header-only, this specific test might not need netflow_switching_lib.
# For consistency and safety, and because PacketBuffer is fundamental, we link netflow_switching_lib.
gtest_discover_tests(buffer_pool_test)
target_include_directories(buffer_pool_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for RoutingManager tests
add_executable(routing_manager_test routing_manager_test.cpp)
target_link_libraries(routing_manager_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(routing_manager_test)
target_include_directories(routing_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for ArpProcessor tests
add_executable(arp_processor_test arp_processor_test.cpp)
target_link_libraries(arp_processor_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(arp_processor_test)
target_include_directories(arp_processor_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for IcmpProcessor tests
add_executable(icmp_processor_test icmp_processor_test.cpp)
target_link_libraries(icmp_processor_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(icmp_processor_test)
target_include_directories(icmp_processor_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for IsisManager tests
add_executable(isis_manager_test isis_manager_test.cpp)
target_link_libraries(isis_manager_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(isis_manager_test)
target_include_directories(isis_manager_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for IsisLsdb tests
add_executable(isis_lsdb_test isis_lsdb_test.cpp)
target_link_libraries(isis_lsdb_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(isis_lsdb_test)
target_include_directories(isis_lsdb_test PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add executable for IsisPdu tests
add_executable(isis_pdu_test isis_pdu_test.cpp)
target_link_libraries(isis_pdu_test PRIVATE netflow_switching_lib GTest::gtest_main)
gtest_discover_tests(isis_pdu_test)
target_include_directories(isis_pdu_test PRIVATE ${CMAKE_SOURCE_DIR}/include)
