# CMake requirements
cmake_minimum_required (VERSION 3.10)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

use_riscv_musl_toolchain(64)

# Generic library information
project (libgroupsig)
get_filename_component(PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR} DIRECTORY)

set (libgroupsig_VERSION_MAJOR 1)
set (libgroupsig_VERSION_MINOR 0)
set (libgroupsig_VERSION_PATCH 0)

# Set the paths for produced libraries and runtime binaries
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# Global compiler flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w -fPIC")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -fPIC")
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif ()

# If -DSHA2 present, use SHA2 in PS16 (original is BLAKE)
if (SHA2)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHA2")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHA2")
endif ()

# If -DSHA3 present, use SHA3 in PS16/KTY04
if (SHA3)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHA3")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHA3")
endif ()
# If -DHW3 present, then pass -DHW3 to gcc (only affects if -DHW present too)
if (HW3)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHW3")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHW3")
endif ()

add_link_options("LINKER:--allow-multiple-definition")

# Add the binary tree to the search path for include files
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/src/include")
# Compiler headers path for mcl
include_directories("${PROJECT_BINARY_DIR}/external/include")
# Compiler library path for mcl
link_directories("${PROJECT_BINARY_DIR}/external/lib")

# Check dependencies

# Add modules
list (APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/tee)

## OpenSSL
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  set(OPENSSL_ROOT_DIR /home/xilinx/openssl-3.0.2)
  include(FindOpenSSL)
endif ()
# find_package(OpenSSL REQUIRED)
include(openssl)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  include_directories(${OPENSSL_INCLUDE_DIR})
  link_directories(/home/xilinx/openssl-3.0.2)
endif ()

## Configure options
option (
  USE_GTEST
  "Build with GoogleTest for testing.")

option (
  USE_GCOV
  "Build with GCov for coverage reporting.")

option (
USE_MCL
"Build a local version of MCL for pairing based crypto."
ON)

## Google Test
if (USE_GTEST)
  #  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
  #  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_TEST_COMPILE_FLAGS}" )
  include (gtest)
endif (USE_GTEST)

## GCOV
if (USE_GCOV)
  include (gcovr)
endif (USE_GCOV)

## MCL
if (USE_MCL)
  include (mcl)
  #  link_directories("${CMAKE_BINARY_DIR}/external/kk/lib")
else ()
  find_package (MCL REQUIRED)
  include_directories(${MCL_INCLUDE_DIRS})
endif (USE_MCL)

## @TODO Is this needed/used?
## CTest
include (CTest)

# Subdirectories
add_subdirectory (${PROJECT_SOURCE_DIR}/src/logger ${PROJECT_BINARY_DIR}/src/logger)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/msg ${PROJECT_BINARY_DIR}/src/msg)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/sys ${PROJECT_BINARY_DIR}/src/sys)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/shim ${PROJECT_BINARY_DIR}/src/shim)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/crypto ${PROJECT_BINARY_DIR}/crypto)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/math ${PROJECT_BINARY_DIR}/math)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/misc ${PROJECT_BINARY_DIR}/misc)
# if -DHW present, then load src/hw code
if (HW)
  add_subdirectory (${PROJECT_SOURCE_DIR}/src/hw)
endif ()
add_subdirectory (${PROJECT_SOURCE_DIR}/src/groupsig ${CMAKE_BINARY_DIR}/src/groupsig)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/tools ${CMAKE_BINARY_DIR}/src/tools)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/test/basic ${CMAKE_BINARY_DIR}/src/test/basic)
