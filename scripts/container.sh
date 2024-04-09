#!/bin/bash

[ -n "$1" ] && CNAME="$1" || \
        CNAME=spirs

[ -n "$2" ] && REPO="$2" || \
        REPO=spirs_tee_sdk

# Update API files in the SDK
cmp -s enclave/gicp/toolbox.c $REPO/enclave/gicp/toolbox.c && (cp enclave/gicp/toolbox.c $REPO/enclave/gicp/ && changed=1)
cp host/gicp_api/{server,client,client_mon}.py $REPO/host/gicp_api/

# Update test files in the SDK
cp host/tests/{.coveragerc,test_static.py} $REPO/host/gicp_api/

RES=host/tests/results
SETUP_LOG=$RES/performance.log
mkdir -p $RES
mv $SETUP_LOG $SETUP_LOG.bak > /dev/null
echo -e "Step;Description;Time([hh:]mm:ss.ss)" > $SETUP_LOG

cont=$(docker ps -q --filter name="^$CNAME$")
if [ -z "$cont" ]; then
    echo "[STEP 1/8] Starting container..."
    /usr/bin/time -f "1;Start up container;%E" -o $SETUP_LOG --append \
                  docker run --name $CNAME -it --rm -d -v $PWD/$REPO:/spirs_tee_sdk spirs_keystone:22.04

    CFG=.config
    DEFCFG=riscv64_cva6_spirs_defconfig
    RUN=run-qemu.sh.in

    echo "[STEP 2/8] Patching..."
    docker cp $CNAME:/keystone/build/buildroot.build/$CFG . && patch -f -u $CFG -i patches/flaskinstall.patch
    docker cp $CFG $CNAME:/keystone/build/buildroot.build/ && rm $CFG

    docker cp $CNAME:/keystone/conf/$DEFCFG . && patch -f -u $DEFCFG -i patches/flaskdefconfig.patch
    docker cp $DEFCFG $CNAME:/keystone/conf/ && rm $DEFCFG

    docker cp $CNAME:/keystone/scripts/$RUN . && patch -f -u $RUN -i patches/flaskport.patch
    docker cp $RUN $CNAME:/keystone/scripts/ && rm $RUN

    echo "[STEP 3/8] Recompiling python3 buildroot"
    /usr/bin/time -f "3;Recompiling python3 buildroot;%E" -o $SETUP_LOG --append \
                  docker exec $CNAME make -C build/buildroot.build python3-dirclean all

    echo "[STEP 4/8] Installing python dependencies"
    /usr/bin/time -f "4;Installing python dependencies;%E" -o $SETUP_LOG  --append \
                  docker exec $CNAME sh -c 'apt update && apt install -y python3-pip && pip install requests pytest pytest-cov pytest-json-report'
    changed=1
fi

if [ -n "$changed" ]; then
    # echo "[STEP 5/8] Building enclave"
    # /usr/bin/time -f "[*] 5;Building enclave;%E" -o $SETUP_LOG  --append \
        # docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build /spirs_tee_sdk && make -C /spirs_tee_sdk/build'

    echo "[STEP 5/8] Building enclave (debug)"
    /usr/bin/time -f "5;Building enclave (debug);%E" -o $SETUP_LOG  --append \
                  docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build /spirs_tee_sdk -DCMAKE_BUILD_TYPE=Debug && make -C /spirs_tee_sdk/build'

    echo "[STEP 6/8] Building libgroupsig"
    /usr/bin/time -f "6;Building libgroupsig;%E" -o $SETUP_LOG  --append \
                  docker exec $CNAME sh -c 'cmake -B /spirs_tee_sdk/build/libgroupsig /spirs_tee_sdk/modules/libgroupsig && make -C /spirs_tee_sdk/build/libgroupsig'

    echo "[STEP 7/8] Building libgroupsig python wrapper"
    /usr/bin/time -f "7;Building libgroupsig python wrapper;%E" -o $SETUP_LOG  --append \
                  docker exec $CNAME sh -c 'cd /spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-cp310-cp310-linux_x86_64.whl'

    echo "[STEP 8/8] Building image"
    /usr/bin/time -f "8;Building image;%E" -o $SETUP_LOG  --append \
                  docker exec $CNAME sh -c 'make -C /spirs_tee_sdk/build -j image'
fi
