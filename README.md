# TEE integration
This repository contains the code needed to test the libgroupsig
library inside the TEE.

- [Setup docker container + QEMU](#setup-docker-container-qemu)
- [Deployment](#deployment)

## Setup docker container + QEMU
### Automated process
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

Finally connect to `spirs` container and run the command to start qemu

```bash
docker exec -it spirs bash
cd /spirs_tee_sdk
make -C build -j qemu
```

### Manual process
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
patch -u spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/pygroupsig/libgroupsig_build.py -i patches/pygroupsig.patch
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
patch -u .config -i patches/flaskinstall.patch
docker cp .config spirs:/keystone/build/buildroot.build/

docker cp spirs:/keystone/conf/riscv64_cva6_spirs_defconfig .
patch -u riscv64_cva6_spirs_defconfig -i patches/flaskdefconfig.patch
docker cp riscv64_cva6_spirs_defconfig spirs:/keystone/conf/

docker cp spirs:/keystone/scripts/run-qemu.sh.in .
patch -u run-qemu.sh.in -i patches/flaskport.patch
docker cp run-qemu.sh.in spirs:/keystone/scripts/
```

Compile buildroot with new changes

```bash
docker exec spirs make -C build/buildroot.build python3-dirclean all
```

Connect to container and compile the project

```bash
docker exec -it spirs bash
cd /spirs_tee_sdk
cmake -B build && make -C build
# Needed to test libgroupsig client
cmake -B build/libgroupsig modules/libgroupsig && make -C build/libgroupsig
apt update && apt install -y python3-pip && python3 -m pip install path requests
cd modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-cp310-cp310-linux_x86_64.whl
make -C build -j image && make -C build -j qemu
```

## Clients
The code of the clients (producers and monitors) can be found under
`host/gicp_api`. There are 3 elements:
- **server.py**: This code runs in the same machine as the TEE. It'll execute the commands
  through `gdemos.ke`
- **client.py**: This is the client used by every entity that is in charge of signing assets.
- **client_mon.py**: This is the client used by entities (monitors) that have the permission to revoke signature identities.

The messages between server and clients must be mutually authenticated. The server must have
access to the CA chain in order to validate client certificates.
> The mutual authentication step can be removed if that is not required.
Clients must send their certificate if they want to register in a group, that
certificate will be validated and, if everything is correct and the entity has the permissions,
the registration will be completed.

> A script named `test.sh` has been created showing a basic demo of the clients.

### Deployment
It's necessary to create the crypto material for each group. The crypto material will be
located in the machine/QEMU in charge of the group (group manager).

These commands serve as an example of deploying the group in QEMU
```bash
# Create the group for producers
./gdemos.ke groupsig -s cpy06
# Create the group for monitors
./gdemos.ke groupsig -s cpy06 -a _mon
# Launch the server
python3 gicp_api/server.py -C path/CERT -K path/KEY -c path/CHAIN
# python3 gicp_api/server.py -C crypto/gms/usr1.crt -K crypto/gms/usr1.key -c path/chain.pem
```
> The machine/QEMU hosting the groups must have python3 and
> python3-flask installed

These commands will be executed in another machine/QEMU by a service
that need to sign assets/evidences/logs
```bash
# Register in group (This must contact the server)
python3 gicp_api/client.py -r
# Sign asset (locally)
python3 gicp_api/client.py -s -a path/ASSET -S path/SIGNATURE
# If needed, it's possible to verify a signature (locally)
python3 gicp_api/client.py -v -a path/ASSET -S path/SIGNATURE
```

These commands will be executed in another machine/QEMU that need to
revoke an identity if service/machine is compromised
```bash
# Register in monitors group (This must contact the server)
python3 gicp_api/client_mon.py -r
# Revoke identity based on signature (This must contact the server)
python3 gicp_api/client_mon.py -R -S path/SIGNATURE
# Check status of signature's identity (This must contact the server)
python3 gicp_api/client_mon.py -t -S path/SIGNATURE

# If needed, the monitor can sign signatures issued by produers (locally)
python3 gicp_api/client_mon.py -s -a path/SIGNATURE -S path/REVOKER_SIGNATURE
# The revoker can verify signatures issued by services (locally)
python3 gicp_api/client_mon.py -v -a path/ASSET -S path/SIGNATURE
```

### Docker
We have prepared docker containers with all the required dependencies to run the
python libgroupsig wrapper

Producers/Services client image
```
docker run --rm -it --network "host" -v $PWD/scripts/producers:/tmp/crypto tee-integration:client-prod -r -C /tmp/crypto/usr1.crt -K /tmp/crypto/usr1.key -H 127.0.0.1
```

Monitors/Revokers client image
```
docker run --rm -it --network "host" -v $PWD/scripts/monitors:/tmp/crypto tee-integration:client-mon -r -C /tmp/crypto/usr1.crt -K /tmp/crypto/usr1.key -H 127.0.0.1
```
