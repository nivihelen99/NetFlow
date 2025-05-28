cmake_minimum_required(VERSION 3.10)
project(NetFlow LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find all source files in the src directory
file(GLOB_RECURSE NETFLOW_SOURCES src/*.cpp src/*.c)

# Add the NetFlow library
add_library(NetFlowLib STATIC ${NETFLOW_SOURCES})

# Ensure the include directory is available for header files
target_include_directories(NetFlowLib PUBLIC include)

# Add executable target for the main example
add_executable(netflow_example examples/main.cpp)

# Link NetFlowLib to the netflow_example executable
target_link_libraries(netflow_example PRIVATE NetFlowLib)

# Enable testing with CTest
enable_testing()

# Example of adding a test
# add_test(NAME UnitTests COMMAND YourTestExecutable) # Replace YourTestExecutable with actual test command

# Option for DPDK integration (example)
# option(WITH_DPDK "Enable DPDK support" OFF)
# if(WITH_DPDK)
    # Add DPDK finding and linking logic here
    # find_package(DPDK REQUIRED)
    # target_link_libraries(YourTarget PRIVATE DPDK::dpdk)
# endif()

# Option for kernel bypass (UIO/VFIO)
# option(WITH_KERNEL_BYPASS "Enable kernel bypass support (UIO/VFIO)" OFF)
# if(WITH_KERNEL_BYPASS)
    # Add kernel bypass related configurations
# endif()

# Add subdirectories for tests if they have their own CMakeLists.txt
# add_subdirectory(tests) # If tests/CMakeLists.txt exists

# Add subdirectories for examples if they have their own CMakeLists.txt
# add_subdirectory(examples) # If examples/CMakeLists.txt exists

# Installation configuration (optional)
# install(TARGETS netflow_example DESTINATION bin)
# install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" DESTINATION share/doc/NetFlow)

# Package generation (optional)
# include(CPack)
