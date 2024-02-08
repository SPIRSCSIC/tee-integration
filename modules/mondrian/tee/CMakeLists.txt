cmake_minimum_required(VERSION 3.10)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

use_riscv_musl_toolchain(64)

project(mondrian)

add_library(mondrianl ../src/mondrian.c ../src/common.c)
add_executable(mondrian ../src/main.c ../src/mondrian.c ../src/common.c)
