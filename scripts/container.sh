#!/bin/bash

[ -n "$1" ] && CNAME="$1" || \
        CNAME=spirs

[ -n "$2" ] && REPO="$2" || \
        REPO=spirs_tee_sdk

cont=$(docker ps -q --filter name="$CNAME")
[ -z "$cont" ] && \
    echo "Starting container..." && \
    docker run --name $CNAME -it --rm -d \
           -v $PWD/$REPO:/spirs_tee_sdk \
           spirs_keystone:22.04

CFG=.config
DEFCFG=riscv64_cva6_spirs_defconfig
RUN=run-qemu.sh.in

echo "Patching..."
docker cp $CNAME:/keystone/build/buildroot.build/$CFG .
patch -u $CFG -i patches/flaskinstall.patch
docker cp $CFG $CNAME:/keystone/build/buildroot.build/
rm $CFG

docker cp $CNAME:/keystone/conf/$DEFCFG .
patch -u $DEFCFG -i patches/flaskdefconfig.patch
docker cp $DEFCFG $CNAME:/keystone/conf/
rm $DEFCFG

docker cp $CNAME:/keystone/scripts/$RUN .
patch -u $RUN -i patches/flaskport.patch
docker cp $RUN $CNAME:/keystone/scripts/
rm $RUN

echo "Recompiling python3 buildroot"
docker exec $CNAME make -C build/buildroot.build python3-dirclean all

echo "Installing python dependencies"
docker exec $CNAME sh -c 'apt update && apt install -y python3-pip && pip install path requests'

echo "Building enclave"
docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build /spirs_tee_sdk && make -C /spirs_tee_sdk/build'

echo "Building libgroupsig"
docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build/libgroupsig /spirs_tee_sdk/modules/libgroupsig && make -C /spirs_tee_sdk/build/libgroupsig'

echo "Building libgroupsig python wrapper"
docker exec $CNAME sh -c 'cd /spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-cp310-cp310-linux_x86_64.whl'

echo "Building image"
docker exec $CNAME sh -c 'make -C /spirs_tee_sdk/build -j image'
