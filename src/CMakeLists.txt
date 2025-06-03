# CMakeLists.txt for the src directory of NetFlowPlusPlus
cmake_policy(VERSION 3.10) # Or your project's minimum version

# --- NetFlow Port Library ---
# InterfaceManager is now header-only. This library might become an INTERFACE library
# or be removed if no other .cpp files are part of it.
# Changing to INTERFACE library as InterfaceManager is now header-only.
add_library(netflow_port_lib INTERFACE)
# No sources needed for an INTERFACE library. Its properties (like include directories) are still used by linkers.
target_include_directories(netflow_port_lib INTERFACE ${CMAKE_SOURCE_DIR}/include) # Changed PUBLIC to INTERFACE

# --- NetFlow Switching Library ---
# This library will contain compiled components related to switching.
add_library(netflow_switching_lib STATIC
    netflow++/packet.cpp # Added new packet utility file
    netflow++/config_manager.cpp
    netflow++/stp_manager.cpp
    netflow++/lacp_manager.cpp # lacp_manager.cpp should also be here from previous work
    netflow++/forwarding_database.cpp
    netflow++/interface_manager.cpp
    netflow++/packet_classifier.cpp
    netflow++/vlan_manager.cpp
    netflow++/arp_processor.cpp   # Added ARP processor source
    netflow++/icmp_processor.cpp  # Added ICMP processor source
    netflow++/routing_manager.cpp # Added Routing Manager source
    netflow++/management_service.cpp # Added Management Service source
    netflow++/lldp_manager.cpp       # Added LLDP Manager source
    netflow++/qos_manager.cpp      # Added QoS Manager source
    netflow++/acl_manager.cpp      # Added ACL Manager source
    netflow++/isis/isis_interface_manager.cpp
    netflow++/isis/isis_lsdb.cpp
    netflow++/isis/isis_manager.cpp
    netflow++/isis/isis_pdu.cpp
    netflow++/isis/isis_spf_calculator.cpp
    netflow++/isis/isis_utils.cpp
    netflow++/isis/isis_pdu_parsing.cpp
    netflow++/isis/isis_pdu_serialization.cpp
)

# Make sure the libraries can find their own headers if they were in src,
# and also project-wide headers from the main 'include' directory.
# The main 'include' directory should already be in the global include path
# from the root CMakeLists.txt (include_directories(include)).
# Common include directories for all libraries defined in this src/CMakeLists.txt
# can be set here or ensure they are inherited from the parent scope (root CMakeLists.txt 'include_directories(include)').
# By specifying PUBLIC, any target that links against these libraries will also get these include directories.

# target_include_directories(netflow_port_lib PUBLIC # This was moved up and changed to INTERFACE
#    ${CMAKE_SOURCE_DIR}/include
# )

target_include_directories(netflow_switching_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/netflow++/third_party # For nlohmann/json used by config_manager
)

# No external dependencies for these libs yet, other than standard library.
# target_link_libraries(netflow_port_lib PUBLIC some_other_library)
# target_link_libraries(netflow_switching_lib PUBLIC some_other_library)


# Optional: Installation for the libraries
# install(TARGETS netflow_port_lib netflow_switching_lib
#    EXPORT NetFlowPlusPlusTargets
#    ARCHIVE DESTINATION lib
#    LIBRARY DESTINATION lib
#    RUNTIME DESTINATION bin  # Usually not for STATIC libs
# )
# install(EXPORT NetFlowPlusPlusTargets
#    FILE NetFlowPlusPlusConfig.cmake
#    NAMESPACE NetFlowPlusPlus::
#    DESTINATION lib/cmake/NetFlowPlusPlus
# )

# End of src/CMakeLists.txt
