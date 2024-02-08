# TEE integration
## Automated process
In order to compile the project, first run the script `setup.sh`

```bash
scripts/setup.sh
```

If you have not compiled the `spirs_keystone:22.04` container yet, you need
to create a file named `token` with your gitlab credentials in the directory `spirs_tee_sdk/docker`,
use the following the format

```
username=your_username
password=your_password_or_token
```

Then compile the container (it will take around 15-20min)

```bash
cd spirs_tee_sdk
DOCKER_BUILDKIT=1 docker build --no-cache --secret=id=gitlab,src=$PWD/docker/token -f docker/Dockerfile -t spirs_keystone:22.04 .
```

After you have compiled the container, run the script `container.sh`

```bash
cd .. # if you are inside spirs_tee_sdk directory
scripts/container.sh
```

Finally connect to `spirs` container and run the compilation command

```bash
docker exec -it spirs bash
cd /spirs_tee_sdk
cmake -B build && make -C build && make -C build -j image && make -C build -j qemu
```

## Manual process
The first step is to clone the
[libgroupsig](https://gitlab.gicp.es/spirs/libgroupsig.git) and
[mondrian](https://gitlab.gicp.es/spirs/mondrian.git) repositories
inside [spirs_tee_sdk](https://gitlab.com/spirs_eu/spirs_tee_sdk) repository

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

Copy the required files to compile our project

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
> Remember that If you have not compiled the `spirs_keystone:22.04` container yet, you need
> to create a file named `token` with your gitlab credentials in the directory `spirs_tee_sdk/docker`,
> use the following the format
> ```
> username=your_username
> password=your_password_or_token
> ```

Launch the container in detached mode

```bash
docker run --name spirs -it --rm -d -v $PWD/spirs_tee_sdk:/spirs_tee_sdk spirs_keystone:22.04
```

> Change the -v path accordingly so `spirs_tee_sdk` directory is mounted inside the container

Patch the buildroot configuration file to install flask, and the run-qemu script

```bash
docker cp spirs:/keystone/build/buildroot.build/.config .
docker cp spirs:/keystone/scripts/run-qemu.sh.in .
patch -u .config -i patches/flaskinstall.patch
patch -u run-qemu.sh.in -i patches/flaskport.patch
docker cp .config spirs:/keystone/build/buildroot.build/
docker cp run-qemu.sh.in spirs:/keystone/scripts/
```

Compile buildroot with new changes

```bash
docker exec spirs make -C build/buildroot.build
```

Connect to container and compile the project

```bash
docker exec -it spirs bash
cd /spirs_tee_sdk
cmake -B build && make -C build && make -C build -j image && make -C build -j qemu
```
