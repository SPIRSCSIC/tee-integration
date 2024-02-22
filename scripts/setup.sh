#!/bin/bash

[ -n "$1" ] && REPO="$1" || \
        REPO=spirs_tee_sdk

clonepatch_sdk() {
    git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk $REPO
    patch -u $REPO/enclave/CMakeLists.txt -i patches/cmakelistsenclave.patch
    patch -u $REPO/host/CMakeLists.txt -i patches/cmakelistshost.patch
    patch -u $REPO/CMakeLists.txt -i patches/cmakelists.patch
    patch -u $REPO/docker/Dockerfile -i patches/dockerfile.patch
    cp groupsig.cmake groupsig_import.cmake $REPO
    cp -r enclave/gicp enclave/ta_callbacks_gicp.c $REPO/enclave/
    cp enclave/include/ta_shared_gicp.h $REPO/enclave/include/
    cp enclave/tee_internal_api/include/tee_ta_api_gicp.h $REPO/enclave/tee_internal_api/include/
    cp -r host/gicp_api host/host_gicp.c $REPO/host/
}

clonepatch_gs() {
    git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git $REPO/modules/libgroupsig
    patch -u $REPO/modules/libgroupsig/src/wrappers/python/pygroupsig/libgroupsig_build.py -i patches/pygroupsig.patch
    cp -r modules/libgroupsig/tee $REPO/modules/libgroupsig
}

clonepatch_md() {
    git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git $REPO/modules/mondrian
    cp -r modules/mondrian/tee $REPO/modules/mondrian
}

[ ! -d $REPO ] && clonepatch_sdk
[ ! -d $REPO/modules/libgroupsig ] && clonepatch_gs
[ ! -d $REPO/modules/mondrian ] && clonepatch_md
