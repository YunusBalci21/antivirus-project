cmake_minimum_required(VERSION 3.10)
project(AntivirusProject)

set(CMAKE_CXX_STANDARD 17)

# Include directories
include_directories(include)

# Add source files
file(GLOB SOURCES src/**/*.cpp)

# Add executable
add_executable(antivirus ${SOURCES})
