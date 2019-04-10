cmake_minimum_required(VERSION 3.13)
project(kind C)

set(CMAKE_C_STANDARD 99)

add_executable(kind main.c state.h cmd.h)
target_link_libraries(kind sodium)