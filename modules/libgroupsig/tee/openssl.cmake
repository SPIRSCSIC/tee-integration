include(ExternalProject)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

use_riscv_musl_toolchain(64)

set(OPENSSL_TARGET linux64-riscv64)
set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)

set(OSSL_CONF_ENV
  CC=${CC}
  CXX=${CXX}
  LD=${LD}
  AR=${AR}
  OBJCOPY=${OBJCOPY}
  OBJDUMP=${OBJDUMP}
)

ExternalProject_Add(OpenSSL
    URL https://www.openssl.org/source/openssl-3.0.8.tar.gz
    URL_HASH SHA256=6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e
    INSTALL_DIR ${EXTERNAL_INSTALL_LOCATION}
    LOG_DOWNLOAD ON
    LOG_INSTALL ON
    CONFIGURE_COMMAND env ${OSSL_CONF_ENV} <SOURCE_DIR>/Configure --prefix=<INSTALL_DIR> no-shared ${OPENSSL_TARGET}
    BUILD_COMMAND make -s -j
    INSTALL_COMMAND make -s install_sw
)

# Set variables for libgroupsig building
set(OPENSSL_LIBRARIES
  ${EXTERNAL_INSTALL_LOCATION}/lib/libssl.a
  ${EXTERNAL_INSTALL_LOCATION}/lib/libcrypto.a
)
