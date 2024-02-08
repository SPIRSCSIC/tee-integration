#!/bin/bash

echo "Starting container..."
docker run --name spirs -it --rm -d \
       -v $PWD/spirs_tee_sdk:/spirs_tee_sdk spirs_keystone:22.04

echo "Patching..."
docker cp spirs:/keystone/build/buildroot.build/.config .
docker cp spirs:/keystone/scripts/run-qemu.sh.in .

patch -u .config -i patches/flaskinstall.patch
patch -u run-qemu.sh.in -i patches/flaskport.patch

docker cp .config spirs:/keystone/build/buildroot.build/ \
    && rm .config
docker cp run-qemu.sh.in spirs:/keystone/scripts/ \
    && rm run-qemu.sh.in

echo "Compiling buildroot..."
docker exec spirs make -C build/buildroot.build
