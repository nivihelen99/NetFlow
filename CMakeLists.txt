cmake_minimum_required(VERSION 3.10)
project(NetFlowPlusPlus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Option to build examples
option(BUILD_EXAMPLES "Build all examples" ON)

# Add the include directory for header files globally for now.
# For more fine-grained control, this could be applied on a per-target basis,
# especially if different parts of the project had different include needs.
# However, for a project of this structure, a global include path for the
# main 'include' directory is often acceptable.
# If libraries were to export their include directories properly (e.g. via install interface),
# executables might not even need this explicitly if they link correctly.
include_directories(include) # Keeping this for simplicity as libs are not exporting install interface yet

if(BUILD_EXAMPLES)
    message(STATUS "Building examples...")

    # Add the executable target for the phase1 example
    add_executable(phase1_packet_usage examples/phase1_packet_usage.cpp)
    # Examples need access to headers in the main 'include' directory.
    # This is covered by the global include_directories(include) for now.
    # If global include_directories was removed, each target would need:
    # target_include_directories(phase1_packet_usage PRIVATE ${CMAKE_SOURCE_DIR}/include)

    # Add the executable target for the phase2 example
    add_executable(phase2_l2_parsing examples/phase2_l2_parsing.cpp)

    # Add the executable target for the phase3 example
    add_executable(phase3_fdb_usage examples/phase3_fdb_usage.cpp)
    target_link_libraries(phase3_fdb_usage PRIVATE netflow_switching_lib)

    # Add the executable target for the phase4 example
    add_executable(phase4_interface_vlan_config examples/phase4_interface_vlan_config.cpp)
    target_link_libraries(phase4_interface_vlan_config PRIVATE netflow_port_lib netflow_switching_lib)

    # Add the executable target for the phase5 example
    add_executable(phase5_l3_forwarding examples/phase5_l3_forwarding.cpp)
    target_link_libraries(phase5_l3_forwarding PRIVATE netflow_switching_lib) # Assuming switching_lib is enough

    # Add the executable target for the phase6 example
    add_executable(phase6_cli_usage examples/phase6_cli_usage.cpp)
    target_link_libraries(phase6_cli_usage PRIVATE netflow_switching_lib)

    # --- Optional: Installation for examples (if BUILD_EXAMPLES is ON) ---
    install(TARGETS phase1_packet_usage phase2_l2_parsing phase3_fdb_usage phase4_interface_vlan_config phase5_l3_forwarding phase6_cli_usage DESTINATION bin)

else()
    message(STATUS "Skipping build of examples.")
endif()


# No explicit libraries to link against in this phase for phase1 & 2,
# but this is where they would be added.
# target_link_libraries(phase1_packet_usage PRIVATE some_library) # Example
# target_link_libraries(phase2_l2_parsing PRIVATE some_library) # Example


# --- Optional: Installation for main library headers (always install these) ---
install(DIRECTORY include/netflow++ DESTINATION include)

# --- Optional: Testing (using CTest) ---
# CTest should only be enabled and tests added if BUILD_EXAMPLES is ON,
# or if there are other tests (e.g. library unit tests)
# Ensure BUILD_EXAMPLES is ON or make enable_testing() unconditional
enable_testing()

if(BUILD_EXAMPLES)
    add_test(NAME ExampleTest1 COMMAND phase1_packet_usage)
    add_test(NAME ExampleTest2 COMMAND phase2_l2_parsing)
    add_test(NAME ExampleTest3 COMMAND phase3_fdb_usage)
    add_test(NAME ExampleTest4 COMMAND phase4_interface_vlan_config)
    add_test(NAME L3ForwardingExample COMMAND phase5_l3_forwarding)
    # (These are very basic tests, real tests would be in the 'tests' directory
    #  and use a testing framework like GTest or Catch2)
endif()

# --- Add GTest using FetchContent ---
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# --- Add subdirectory for src files ---
# This must be done before defining targets (like examples) that depend on libraries built in src.
add_subdirectory(src)

# --- Add our main application executable ---
add_executable(netflow_app src/main.cpp)
target_link_libraries(netflow_app PRIVATE netflow_switching_lib)
# Ensure it can find headers from the 'include' directory (already covered by global include_directories(include))
# target_include_directories(netflow_app PRIVATE ${CMAKE_SOURCE_DIR}/include) # Explicitly if needed

install(TARGETS netflow_app DESTINATION bin) # Optional: install the app


# --- Optional: Add subdirectory for tests ---
add_subdirectory(tests)

# --- Optional: Add subdirectory for benchmarks ---
# add_subdirectory(benchmarks)

# --- Optional: Add subdirectory for examples ---
# (We've added the example directly here, but for many examples,
# a subdirectory is cleaner)
# add_subdirectory(examples)
#  and use a testing framework like GTest or Catch2)

# --- Optional: Add subdirectory for tests ---
# add_subdirectory(tests)

# --- Optional: Add subdirectory for benchmarks ---
# add_subdirectory(benchmarks)

# --- Optional: Add subdirectory for examples ---
# (We've added the example directly here, but for many examples,
# a subdirectory is cleaner)
# add_subdirectory(examples)
