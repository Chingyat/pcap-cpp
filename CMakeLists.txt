cmake_minimum_required(VERSION 3.5)

project (PCapPP CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(PCap REQUIRED)

add_subdirectory(src)
add_subdirectory(test)
