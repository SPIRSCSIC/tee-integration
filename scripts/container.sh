#!/bin/bash

[ -n "$1" ] && CNAME="$1" || \
        CNAME=spirs

[ -n "$2" ] && REPO="$2" || \
        REPO=spirs_tee_sdk

time_log="host/tests/results/performance.log"
mkdir -p host/tests/results 2> /dev/null
mv $time_log $time_log.bak 2> /dev/null
echo -e "EXECUTION TIME LOGS\nStep;Desc;m:s" > $time_log

cont=$(docker ps -q --filter name="$CNAME")
[ -z "$cont" ] && \
    echo "[*] Starting container... [STEP 1/8]" && \
    /usr/bin/time -f "1;Start up container; %E" -o $time_log --append \
    docker run --name $CNAME -it --rm -d \
           -v $PWD/$REPO:/spirs_tee_sdk \
           spirs_keystone:22.04

CFG=.config
DEFCFG=riscv64_cva6_spirs_defconfig
RUN=run-qemu.sh.in

echo "[*] Patching... [STEP 2/8]"
docker cp $CNAME:/keystone/build/buildroot.build/$CFG .
patch -f -u $CFG -i patches/flaskinstall.patch
docker cp $CFG $CNAME:/keystone/build/buildroot.build/
rm $CFG

docker cp $CNAME:/keystone/conf/$DEFCFG .
patch -f -u $DEFCFG -i patches/flaskdefconfig.patch
docker cp $DEFCFG $CNAME:/keystone/conf/
rm $DEFCFG

docker cp $CNAME:/keystone/scripts/$RUN .
patch -f -u $RUN -i patches/flaskport.patch
docker cp $RUN $CNAME:/keystone/scripts/
rm $RUN

echo "[*] Recompiling python3 buildroot [STEP 3/8]"
/usr/bin/time -f "3;Recompiling python3 buildroot; %E" -o $time_log --append \
  docker exec $CNAME make -C build/buildroot.build python3-dirclean all

echo "[*] Installing python dependencies [STEP 4/8]"
/usr/bin/time -f "4;Installing python dependencies; %E" -o $time_log  --append \
  docker exec $CNAME sh -c 'apt update && apt install -y python3-pip && pip install requests pytest pytest-cov pytest-json-report'

# echo "[*] Building enclave [step 5/8]"
#/usr/bin/time -f "[*] 5;Building enclave; %E" -o $time_log  --append \
# docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build /spirs_tee_sdk && make -C /spirs_tee_sdk/build'

echo "[*] Building enclave (debug) [STEP 5/8]"
/usr/bin/time -f "5;Building enclave (debug); %E" -o $time_log  --append \
  docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build /spirs_tee_sdk -DCMAKE_BUILD_TYPE=Debug && make -C /spirs_tee_sdk/build'

echo "[*] Building libgroupsig [STEP 6/8]"
/usr/bin/time -f "6;Building libgroupsig; %E" -o $time_log  --append \
  docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build/libgroupsig /spirs_tee_sdk/modules/libgroupsig && make -C /spirs_tee_sdk/build/libgroupsig'

echo "[*] Building libgroupsig python wrapper [STEP 7/8]"
/usr/bin/time -f "7;Building libgroupsig python wrapper; %E" -o $time_log  --append \
  docker exec $CNAME sh -c 'cd /spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-cp310-cp310-linux_x86_64.whl'

echo "[*] Building image [STEP 8/8]"
/usr/bin/time -f "8;Building image; %E" -o $time_log  --append \
  docker exec $CNAME sh -c 'make -C /spirs_tee_sdk/build -j image'
