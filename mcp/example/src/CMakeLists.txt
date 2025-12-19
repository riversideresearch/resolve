# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

cmake_minimum_required(VERSION 3.10)
project(ExampleProject VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

set(CMAKE_BUILD_TYPE Debug)

add_executable(example_app main.c)

install(TARGETS example_app DESTINATION bin)
