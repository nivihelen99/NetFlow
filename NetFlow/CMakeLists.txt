cmake_minimum_required(VERSION 3.10)
project(NetFlow LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define include directories
include_directories(include)

# Add more build instructions here as the project grows
# For example, adding executables or libraries:
# add_executable(netflow_example examples/main.cpp)
# target_link_libraries(netflow_example PRIVATE NetFlow::core) # Assuming you create a library target

# Placeholder for future library targets
# add_library(NetFlowCore INTERFACE) # Or STATIC/SHARED
# target_include_directories(NetFlowCore INTERFACE include)
# if(TARGET NetFlow::core)
#   target_sources(NetFlow::core INTERFACE
#       # List header files if it's an INTERFACE library or source files for STATIC/SHARED
#   )
# endif()

# Enable testing with CTest
enable_testing()

# Example of adding a test
# add_test(NAME UnitTests COMMAND YourTestExecutable) # Replace YourTestExecutable with actual test command

# Option for DPDK integration (example)
option(WITH_DPDK "Enable DPDK support" OFF)
if(WITH_DPDK)
    # Add DPDK finding and linking logic here
    # find_package(DPDK REQUIRED)
    # target_link_libraries(YourTarget PRIVATE DPDK::dpdk)
endif()

# Option for kernel bypass (UIO/VFIO)
option(WITH_KERNEL_BYPASS "Enable kernel bypass support (UIO/VFIO)" OFF)
if(WITH_KERNEL_BYPASS)
    # Add kernel bypass related configurations
endif()

# Add subdirectories for tests if they have their own CMakeLists.txt
# add_subdirectory(tests) # If tests/CMakeLists.txt exists

# Add subdirectories for examples if they have their own CMakeLists.txt
# add_subdirectory(examples) # If examples/CMakeLists.txt exists

# Installation configuration (optional)
# install(TARGETS netflow_example DESTINATION bin)
# install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" DESTINATION share/doc/NetFlow)

# Package generation (optional)
# include(CPack)
