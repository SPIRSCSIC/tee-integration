# TEE integration
The first step is cloning the
[libgroupsig](https://gitlab.gicp.es/spirs/libgroupsig.git) repository and
[mondrian](https://gitlab.gicp.es/spirs/mondrian.git)
inside the [spirs_tee_sdk](https://gitlab.com/spirs_eu/spirs_tee_sdk) repository

```bash
git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk
git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git spirs_tee_sdk/modules/libgroupsig
git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git spirs_tee_sdk/modules/mondrian
```

Patch CMakeLists.txt files from the sdk to include our changes

```bash
patch -u spirs_tee_sdk/enclave/CMakeLists.txt -i patches/cmakelistsenclave.patch
patch -u spirs_tee_sdk/host/CMakeLists.txt -i patches/cmakelistshost.patch
patch -u spirs_tee_sdk/CMakeLists.txt -i patches/cmakelists.patch
patch -u spirs_tee_sdk/docker/Dockerfile -i patches/dockerfile.patch
```

Copy the files with the instructions on how to compile our project:

```bash
cp -r modules/libgroupsig/tee spirs_tee_sdk/modules/libgroupsig
cp -r modules/mondrian/tee spirs_tee_sdk/modules/mondrian
cp groupsig.cmake groupsig_import.cmake spirs_tee_sdk
cp -r enclave/gicp enclave/ta_callbacks_gicp.c spirs_tee_sdk/enclave/
cp enclave/include/ta_shared_gicp.h spirs_tee_sdk/enclave/include/
cp enclave/tee_internal_api/include/tee_ta_api_gicp.h spirs_tee_sdk/enclave/tee_internal_api/include/
cp -r host/gicp_api host/host_gicp.c spirs_tee_sdk/host/
```

Compile the container following the instruction in `spirs_tee_sdk/docker`

```bash
cd spirs_tee_sdk
DOCKER_BUILDKIT=1 docker build --no-cache --secret=id=gitlab,src=$PWD/docker/token -f docker/Dockerfile -t spirs_keystone:22.04 .
```

Launch the container and build the project

```bash
docker run --name spirs -it --rm -v $PWD/spirs_tee_sdk:/spirs_tee_sdk spirs_keystone:22.04
```

> Change the -v path accordingly so `spirs_tee_sdk` directory is mounted inside the container

In another shell, patch the buildroot configuration file to install flask and the run-qemu script

```bash
docker cp spirs:/keystone/build/buildroot.build/.config .
docker cp spirs:/keystone/scripts/run-qemu.sh.in .
patch -u .config -i patches/flaskinstall.patch
patch -u run-qemu.sh.in -i patches/flaskport.patch
docker cp .config spirs:/keystone/build/buildroot.build/
docker cp run-qemu.sh.in spirs:/keystone/scripts/
```

Inside the container, we need to compile the buildroot with the new changes

```bash
make -C build/buildroot.build
```

Finally, compile the project

```bash
cd /spirs_tee_sdk
cmake -B build && make -C build && make -C build -j image && make -C build -j qemu
```
