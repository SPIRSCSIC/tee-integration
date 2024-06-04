#!/bin/bash

CNAME=spirs
REPO=spirs_tee_sdk
IMAGE=glcr.gicp.es/spirs/tee-integration:norepo
OUT=/dev/null
RES=host/tests/results
SETUP_LOG=$RES/performance.log
PORT=5000
mkdir -p $RES
mv $SETUP_LOG $SETUP_LOG.bak > /dev/null
echo -e "Step;Description;Time([hh:]mm:ss.ss)" > $SETUP_LOG

clone_dep () {
    [ ! -d "$REPO" ] && \
        git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk "$REPO" && \
        patch_sdk
    [ ! -d "$REPO/modules/libgroupsig" ] && \
        git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git "$REPO/modules/libgroupsig" && \
        patch_gs
    [ ! -d "$REPO/modules/mondrian" ] && \
        git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git "$REPO/modules/mondrian" && \
        patch_mon
    [ -n "$patch_sdk" ] && patch_sdk
    [ -n "$patch_gs" ] && patch_gs
    [ -n "$patch_mon" ] && patch_mon
}

patch_sdk () {
    cp groupsig.cmake groupsig_import.cmake "$REPO"
    cp -r enclave/{gicp,ta_callbacks_gicp.c} "$REPO/enclave/"
    cp enclave/include/ta_shared_gicp.h "$REPO/enclave/include/"
    cp enclave/tee_internal_api/include/tee_ta_api_gicp.h "$REPO/enclave/tee_internal_api/include/"
    cp -r host/{gicp_api,host_gicp.c} "$REPO/host/"
    (cd scripts && ./crypto.sh gms monitors producers)
    mkdir -p "$REPO/crypto" && cp -r scripts/{gms,monitors,producers,chain.pem} "$REPO/crypto"
    patch -u "$REPO/enclave/CMakeLists.txt" -i patches/cmakelistsenclave.patch
    patch -u "$REPO/host/CMakeLists.txt" -i patches/cmakelistshost.patch
    patch -u "$REPO/CMakeLists.txt" -i patches/cmakelists.patch
}

patch_mon () {
    cp -r modules/mondrian/tee "$REPO/modules/mondrian"
}

patch_gs () {
    cp -r modules/libgroupsig/tee "$REPO/modules/libgroupsig"
    patch -u "$REPO/modules/libgroupsig/src/wrappers/python/pygroupsig/libgroupsig_build.py" -i patches/pygroupsig.patch
}

usage () {
    echo "Usage: container.sh [-r|--repo DIR] [-n|--name NAME] [-b|--build] [--verbose] [--debug] [-h]"
    echo
    echo "       -t|--test        Install pytest dependencies"
    echo "       -r|--repo DIR    Location of the repository to mount in the container"
    echo "       -n|--name NAME   Name to use when launching the container"
    echo "       -b|--build       Force rebuilding libgroupsig and tee application"
    echo "       -p|--port        Change default listening port of the server"
    echo "       --verbose        Increase verbosity of script"
    echo "       --debug          Enable shell script debug mode"
    exit $1
}

while [ $# -gt 0 ]; do
    case $1 in
        -t|--test)
            _test=1
            shift
            ;;
        -r|--repo)
            REPO="$2"
            shift 2
            ;;
        -n|--name)
            CNAME="$2"
            shift 2
            ;;
        -b|--build)
            _build=1
            shift
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --verbose)
            OUT=/dev/tty
            shift
            ;;
        --debug)
            set -x
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[!] Parameter $1 not recognized"
            usage 1
            ;;
    esac
done

clone_dep
# Update API files in the SDK
cmp -s enclave/gicp/toolbox.c "$REPO/enclave/gicp/toolbox.c" || (cp enclave/gicp/toolbox.c "$REPO/enclave/gicp/" && changed=1)
cp host/gicp_api/{server,client,client_mon}.py "$REPO/host/gicp_api/"

if [ -n "$_test" ]; then
    # Update test files in the SDK
    cp host/tests/{.coveragerc,test_static.py} "$REPO/host/gicp_api/"
fi

cont=$(docker ps -q --filter name="^$CNAME$")
if [ -z "$cont" ]; then
    echo "[STEP 1/2] Starting container..."
    /usr/bin/time -f "1;Start up container;%E" -o $SETUP_LOG --append \
                  docker run --name "$CNAME" -it --rm -d -p $PORT:5000 -v "$PWD/$REPO":/spirs_tee_sdk "$IMAGE"

    echo "[STEP 2/2] Installing python dependencies"
    if [ -n "$_test" ]; then
        extra="pytest pytest-cov pytest-json-report"
    fi
    docker exec "$CNAME" sh -c "test -f /spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/dist/pygroupsig-1.1.0-*.whl"
    [ $? -eq 0 ] && extra="$extra /spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/dist/pygroupsig-1.1.0-*.whl"
    /usr/bin/time -f "2;Installing python dependencies;%E" -o $SETUP_LOG  --append \
                  docker exec "$CNAME" sh -c "apt update -qq && apt install -y python3 python3-dev python3-pip && pip install requests $extra" > $OUT 2>&1
fi

if [ ! -d "$REPO/build" ] || [ -n "$changed" ] || [ -n "$_build" ]; then
    # echo "[STEP 1/4] Building enclave (debug)"
    # /usr/bin/time -f "5;Building enclave (debug);%E" -o $SETUP_LOG  --append \
    #               docker exec "$CNAME" sh -c 'cmake -B build -DCMAKE_BUILD_TYPE=Debug && make -C build' > $OUT 2>&1

    echo "[STEP 1/4] Building enclave"
    /usr/bin/time -f "1;Building enclave;%E" -o $SETUP_LOG  --append \
                  docker exec "$CNAME" sh -c 'cmake -B build && make -C build' > $OUT 2>&1

    echo "[STEP 2/4] Building libgroupsig"
    /usr/bin/time -f "2;Building libgroupsig;%E" -o $SETUP_LOG  --append \
                  docker exec "$CNAME" sh -c 'cmake -B build/libgroupsig modules/libgroupsig && make -C build/libgroupsig' > $OUT 2>&1

    echo "[STEP 3/4] Building libgroupsig python wrapper"
    /usr/bin/time -f "3;Building libgroupsig python wrapper;%E" -o $SETUP_LOG  --append \
                  docker exec "$CNAME" sh -c 'cd modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-*.whl' > $OUT 2>&1

    echo "[STEP 4/4] Building image"
    /usr/bin/time -f "4;Building image;%E" -o $SETUP_LOG  --append \
                  docker exec "$CNAME" sh -c 'make -C build -j image' > $OUT 2>&1
fi
