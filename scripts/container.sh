#!/bin/bash

# echo "Starting container..."
# docker run --name spirs -it --rm -d \
#        -v $PWD/spirs_tee_sdk:/spirs_tee_sdk spirs_keystone:22.04

echo "Patching..."
docker cp spirs:/keystone/build/buildroot.build/.config .
docker cp spirs:/keystone/conf/riscv64_cva6_spirs_defconfig .
docker cp spirs:/keystone/scripts/run-qemu.sh.in .

patch -u .config -i patches/flaskinstall.patch
patch -u riscv64_cva6_spirs_defconfig -i patches/flaskdefconfig.patch
patch -u run-qemu.sh.in -i patches/flaskport.patch

docker cp .config spirs:/keystone/build/buildroot.build/
docker cp riscv64_cva6_spirs_defconfig spirs:/keystone/conf/
docker cp run-qemu.sh.in spirs:/keystone/scripts/

echo "Recompiling python3 buildroot..."
docker exec spirs make -C build/buildroot.build python3-dirclean all
