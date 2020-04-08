cmake_minimum_required(VERSION 3.14)
project(random C)

set(CMAKE_C_STANDARD 90)

include_directories(../../include)
add_executable(random main.c)
