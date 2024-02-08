#!/bin/bash

clonepatch_sdk() {
    git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk
    patch -u spirs_tee_sdk/enclave/CMakeLists.txt -i patches/cmakelistsenclave.patch
    patch -u spirs_tee_sdk/host/CMakeLists.txt -i patches/cmakelistshost.patch
    patch -u spirs_tee_sdk/CMakeLists.txt -i patches/cmakelists.patch
    patch -u spirs_tee_sdk/docker/Dockerfile -i patches/dockerfile.patch
    cp groupsig.cmake groupsig_import.cmake spirs_tee_sdk
    cp -r enclave/gicp enclave/ta_callbacks_gicp.c spirs_tee_sdk/enclave/
    cp enclave/include/ta_shared_gicp.h spirs_tee_sdk/enclave/include/
    cp enclave/tee_internal_api/include/tee_ta_api_gicp.h spirs_tee_sdk/enclave/tee_internal_api/include/
    cp -r host/gicp_api host/host_gicp.c spirs_tee_sdk/host/
}

clonepatch_gs() {
    git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git spirs_tee_sdk/modules/libgroupsig
    cp -r modules/libgroupsig/tee spirs_tee_sdk/modules/libgroupsig
}

clonepatch_md() {
    git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git spirs_tee_sdk/modules/mondrian
    cp -r modules/mondrian/tee spirs_tee_sdk/modules/mondrian
}

[ ! -d spirs_tee_sdk ] && clonepatch_sdk
[ ! -d spirs_tee_sdk/modules/libgroupsig ] && clonepatch_gs
[ ! -d spirs_tee_sdk/modules/mondrian ] && clonepatch_md
