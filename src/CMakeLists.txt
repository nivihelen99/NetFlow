# CMakeLists.txt for the src directory of NetFlowPlusPlus
cmake_policy(VERSION 3.10) # Or your project's minimum version

# --- NetFlow Port Library ---
add_library(netflow_port_lib STATIC
    port/interface_manager.cpp
)

# --- NetFlow Switching Library ---
# This library will contain compiled components related to switching, like the FDB and VLAN Manager.
add_library(netflow_switching_lib STATIC
    switching/fdb.cpp
    switching/vlan_manager.cpp
    netflow++/config_manager.cpp # Added ConfigManager source
)

# Make sure the libraries can find their own headers if they were in src,
# and also project-wide headers from the main 'include' directory.
# The main 'include' directory should already be in the global include path
# from the root CMakeLists.txt (include_directories(include)).
# Common include directories for all libraries defined in this src/CMakeLists.txt
# can be set here or ensure they are inherited from the parent scope (root CMakeLists.txt 'include_directories(include)').
# By specifying PUBLIC, any target that links against these libraries will also get these include directories.

target_include_directories(netflow_port_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_include_directories(netflow_switching_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
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
