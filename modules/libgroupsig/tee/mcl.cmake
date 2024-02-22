include(ExternalProject)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

use_riscv_musl_toolchain(64)

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)
set(MCL_CONF_ENV
  CC=${CC}
  CXX=${CXX}
  LD=${LD}
  AR=${AR}
  OBJCOPY=${OBJCOPY}
  OBJDUMP=${OBJDUMP}
  ARCH=linux64-riscv64
  MCL_BINT_ASM=0
  MCL_USE_LLVM=0
)

ExternalProject_Add(mclproject
  URL https://github.com/herumi/mcl/archive/refs/tags/v1.84.0.tar.gz
  URL_HASH SHA256=dc655c2eb5b2426736d8ab92ed501de0ac78472f1ee7083919a98a8aca3e76a3
  BUILD_IN_SOURCE 1
  LOG_DOWNLOAD ON
  CONFIGURE_COMMAND ""
  BUILD_COMMAND env ${MCL_CONF_ENV} make -s -j
  INSTALL_COMMAND ""
  COMMAND ${CMAKE_COMMAND} -E copy_directory
      <SOURCE_DIR>/lib ${EXTERNAL_INSTALL_LOCATION}/lib
  COMMAND ${CMAKE_COMMAND} -E copy_directory
      <SOURCE_DIR>/include ${EXTERNAL_INSTALL_LOCATION}/include
)

# Set variables for libgroupsig building
set(MCL_LIBRARY ${EXTERNAL_INSTALL_LOCATION}/lib/libmcl.so)
set(MCL384_256_LIBRARY ${EXTERNAL_INSTALL_LOCATION}/lib/libmclbn384_256.so)
