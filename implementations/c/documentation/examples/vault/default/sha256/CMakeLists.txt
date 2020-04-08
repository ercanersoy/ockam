cmake_minimum_required(VERSION 3.14)
project(sha256 C)

set(CMAKE_C_STANDARD 90)

include_directories(../../include)
add_executable(sha256 main.c)
