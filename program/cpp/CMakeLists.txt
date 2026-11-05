cmake_minimum_required(VERSION 3.11.0)
project(programs CXX)

include(micro/micro.cmake)

# Programs are built here

add_micro_binary(basic basic.cpp)

add_micro_binary(js js.cpp)

add_micro_binary(jwt jwt.cpp)

add_micro_binary(manifest manifest.cpp)
