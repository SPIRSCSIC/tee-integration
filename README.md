# TEE integration
This repository contains the code needed to test the libgroupsig
library inside the TEE.

- [Setup docker container + QEMU](#setup-docker-container-qemu)
    - [Manual process](#manual-process)
        - [Using preconfigured image](#using-preconfigured-image)
        - [Mounting your own repository](#mounting-your-own-repository)
        - [Post configuration](#post-configuration)
    - [Automated process](#automated-process)
- [API](#api)
- [Clients](#clients)
    - [Deployment](#deployment)
      - [Option 1: Command line interface (CLI)](#option-1-command-line-interface-cli)
      - [Option 2: Python library](#option-2-python-library)
    - [Docker](#docker)
- [Tests](#tests)

## Setup docker container
We have prepared several container images with the preconfigured QEMU. We provide an
image with everything packed and another one where the repository must be mounted.

### Manual process
#### Using preconfigured image
Run `glcr.gicp.es/spirs/tee-integration:latest` container in detached mode
```bash
docker run --name spirs -it --rm -d -p 5000:5000 glcr.gicp.es/spirs/tee-integration:latest
```
> If you want some sort of persistence, you have to bind-mount the file/directories in the container

Connect to the container and compile the project
```bash
docker exec -it spirs bash
make -C build -j qemu
```

#### Mounting your own repository
The first step is to clone the dependencies,
[libgroupsig](https://gitlab.gicp.es/spirs/libgroupsig.git) and
[mondrian](https://gitlab.gicp.es/spirs/mondrian.git)
inside [spirs_tee_sdk](https://gitlab.com/spirs_eu/spirs_tee_sdk) repository
```bash
git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk
git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git spirs_tee_sdk/modules/libgroupsig
git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git spirs_tee_sdk/modules/mondrian
```

Copy the required files to compile our project
```bash
cp groupsig.cmake groupsig_import.cmake spirs_tee_sdk
cp -r enclave/{gicp,ta_callbacks_gicp.c} spirs_tee_sdk/enclave/
cp enclave/include/ta_shared_gicp.h spirs_tee_sdk/enclave/include/
cp enclave/tee_internal_api/include/tee_ta_api_gicp.h spirs_tee_sdk/enclave/tee_internal_api/include/
cp -r host/{gicp_api,host_gicp.c} spirs_tee_sdk/host/
cp -r modules/libgroupsig/tee spirs_tee_sdk/modules/libgroupsig
cp -r modules/mondrian/tee spirs_tee_sdk/modules/mondrian
```

Patch `CMakeLists.txt` to include our changes
```bash
patch -u spirs_tee_sdk/enclave/CMakeLists.txt -i patches/cmakelistsenclave.patch
patch -u spirs_tee_sdk/host/CMakeLists.txt -i patches/cmakelistshost.patch
patch -u spirs_tee_sdk/CMakeLists.txt -i patches/cmakelists.patch
patch -u spirs_tee_sdk/modules/libgroupsig/src/wrappers/python/pygroupsig/libgroupsig_build.py -i patches/pygroupsig.patch
```

Generate the crypto material for the demo
```bash
(cd scripts && ./crypto.sh gms monitors producers)
mkdir -p spirs_tee_sdk/crypto && cp -r scripts/{gms,monitors,producers,chain.pem} spirs_tee_sdk/crypto
```

Launch the `glcr.gicp.es/spirs/tee-integration:norepo` container in detached mode
```bash
docker run --name spirs -it --rm -d -p 5000:5000 -v $PWD/spirs_tee_sdk:/spirs_tee_sdk glcr.gicp.es/spirs/tee-integration:norepo
```
> Change the -v path accordingly so `spirs_tee_sdk` directory is mounted inside the container

Connect to the container and compile the project
```bash
docker exec -it spirs bash
cmake -B build && make -C build
make -C build -j image && make -C build -j qemu
```

#### Post configuration
If you want to execute the clients from the container, you will need to compile libgroupsig in a "normal" way,
using x86\_64 gcc, install python dependencies, compile the python wrapper and install the generated wheel.
```bash
docker exec -it spirs bash
cmake -B build/libgroupsig modules/libgroupsig && make -C build/libgroupsig
apt update -qq && apt install -y python3-dev python3-pip requests
cd modules/libgroupsig/src/wrappers/python/ && python3 setup.py bdist_wheel && pip install dist/pygroupsig-1.1.0-*.whl
```

### Automated process (compile library)
Run the script `scripts/container.sh`
```bash
# cd .. # if you are inside spirs_tee_sdk directory
scripts/container.sh
```

Finally connect to `spirs` container and run the command to start qemu
```bash
docker exec -it spirs bash
make -C build -j qemu
```

## API
We have uploaded the API specification using the OpenAPI v3 standard. Check it
at https://app.swaggerhub.com/apis/schica/groupsig/1.0.0

> **Note**: There are two functions offered in the `gdemos.ke` executable that are not available
> in the API: `--sign/--verify`, these functions are provided as a way to
> sign/verify without using python library, however it is very inadvisable due
> to the overhead added when creating+opening a connection with the TA (slow) and
> the fact that you would need to have access to a member key.
> ```bash
> ./gdemos.ke groupsig --sign /root/sig --asset /root/asset --mkey /root/mkey
> ./gdemos.ke groupsig --verify /root/sig --asset /root/asset
> ```
> In a future iteration of the library, we aim to move this functionality to the RA so that
> the overhead added by the TA is removed.

## Clients
The code of the clients (producers and monitors) can be found under
`host/gicp_api`. There are 3 elements:
- `server.py`: This code runs in the same machine as the TEE. It'll execute the commands
  through `gdemos.ke`
- `client.py`: This is the client used by every entity that is in charge of signing assets.
- `client_mon.py`: This is the client used by entities (monitors) that have the permission to revoke signature identities.

The messages between server and clients must be mutually authenticated. The server must have
access to the CA chain in order to validate client certificates.
> The mutual authentication step can be removed if that is not required.

Clients must send their certificate if they want to register in a group, that
certificate will be validated and, if everything is correct and the entity has the permissions,
the registration will be completed.
> Two scripts, named `test.sh` and `test.py`, have been included to show the basic usage of the clients,
> as CLI and as a library respectively.

### Deployment
It is necessary to create the crypto material for each group. The crypto material will be
located in the machine/QEMU in charge of the group (group manager).

These commands serve as an example of deploying the group in QEMU
```bash
# Create the group for producers
./gdemos.ke groupsig -s cpy06
# Create the group for monitors
./gdemos.ke groupsig -s cpy06 -a _mon
# Launch the server
python3 gicp_api/server.py -C path/CERT -K path/KEY -c path/CHAIN
# python3 gicp_api/server.py -C crypto/gms/usr1.crt -K crypto/gms/usr1.key -c crypto/chain.pem
```
> The machine/QEMU hosting the groups must have python3 and
> python3-flask installed

Now, regarding the clients, there are two ways to execute them.

#### Option 1: Command line interface (CLI)
These commands will be executed in another machine/QEMU by a service
that needs to sign assets/evidences/logs.

```bash
# Register in group (This must contact the server)
python3 gicp_api/client.py -r -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client.py -r -C crypto/producers/usr1.crt -K crypto/producers/usr1.key -H localhost
# Sign asset (locally)
python3 gicp_api/client.py -s -a path/ASSET -S path/SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client.py -s -a asset -S sig -C crypto/producers/usr1.crt -K crypto/producers/usr1.key -H localhost
# If needed, it's possible to verify a signature (locally)
python3 gicp_api/client.py -v -a path/ASSET -S path/SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client.py -v -a asset -S sig -C crypto/producers/usr1.crt -K crypto/producers/usr1.key -H localhost
```

These commands will be executed in another machine/QEMU that needs to
revoke an identity if service/machine is compromised.

```bash
# Register in monitors group (This must contact the server)
python3 gicp_api/client_mon.py -r -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client_mon.py -r -C crypto/monitors/usr1.crt -K crypto/monitors/usr1.key -H localhost
# Revoke identity based on signature (This must contact the server)
python3 gicp_api/client_mon.py -R -S path/SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client_mon.py -R -S sig -C crypto/monitors/usr1.crt -K crypto/monitors/usr1.key -H localhost
# Check status of signature's identity (This must contact the server)
python3 gicp_api/client_mon.py -t -S path/SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client_mon.py -t -S sig -C crypto/monitors/usr1.crt -K crypto/monitors/usr1.key -H localhost

# If needed, the monitor can sign signatures issued by producers (locally)
python3 gicp_api/client_mon.py -s -a path/SIGNATURE -S path/MONITOR_SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client_mon.py -s -a sig -S sig_mon -C crypto/monitors/usr1.crt -K crypto/monitors/usr1.key -H localhost
# The revoker can verify signatures issued by services (locally)
python3 gicp_api/client_mon.py -v -a path/ASSET -S path/SIGNATURE -C path/CERT -K path/KEY -H localhost
# python3 gicp_api/client_mon.py -v -a asset -S sig -C crypto/monitors/usr1.crt -K crypto/monitors/usr1.key -H localhost
```

We have prepared a small demo showing the functionality

Start containers and compile the groupsig library
<a href="https://asciinema.gicp.es/a/0oFaa9m41xD2RDogANcIYqfqN" target="_blank">
    <img src="https://asciinema.gicp.es/a/0oFaa9m41xD2RDogANcIYqfqN.svg"/>
</a>

Generate groups and start servers. Register entities and sign/verify/revoke/check-status
<a href="https://asciinema.gicp.es/a/ScPazISYoF3ZeREG6SbXLxqzJ" target="_blank">
    <img src="https://asciinema.gicp.es/a/ScPazISYoF3ZeREG6SbXLxqzJ.svg"/>
</a>

#### Option 2: Python library
These commands will be executed in another machine/QEMU by a service
that needs to sign assets/evidences/logs.

```python
import host.gicp_api.client as client

PCRT = "crypto/producers/usr1.crt"
PKEY = "crypto/producers/usr1.key"

# Initialize a Producer (requires an active server, a public certificate and its private key)
prod = client.Producer('localhost', PCRT, PKEY)
# Register in monitors group (This must contact the server)
prod.register()
# Sign asset (locally) and saves the signature in file "sig" (default behaviour)
prod.sign(asset='gkey')
# Sign asset (locally) and save the signature in a custom file
prod.sign(asset='gkey', sig='output/file')
# If needed, it's possible to verify a signature (locally)
# If no signature file is specified, it will look for the default signature file "sig"
prod.verify(asset='gkey', sig='output/file')
```

These commands will be executed in another machine/QEMU that need to
revoke an identity if service/machine is compromised.

```python
import host.gicp_api.client_mon as client_mon

MCRT = "../crypto/monitors/usr1.crt"
MKEY = "../crypto/monitors/usr1.key"

# Initialize a Producer (requires an active server, a public certificate and its private key)
mon = client_mon.Monitor('localhost', MCRT, MKEY)
# Register in monitors group (This must contact the server)
mon.register()
# Revoke identity based on signature (This must contact the server)
mon.revoke(sig='output/sigfile')
# Check status of signature's identity (This must contact the server)
mon.status(sig='output/sigfile')
# If needed, the monitor can sign signatures issued by producers (locally)
mon.sign(asset='output/asset', sig='sig_mon')
# The revoker can verify signatures issued by services (locally)
mon.verify(asset='output/asset', sig='output/sigfile')
```

### Docker
We have prepared docker containers with all the required dependencies to run the
python libgroupsig wrapper

Producers/Services client image
```bash
docker run --rm -it --network "host" -v $PWD/scripts/producers:/tmp/crypto glcr.gicp.es/spirs/tee-integration:client-prod -r -C /tmp/crypto/usr1.crt -K /tmp/crypto/usr1.key -H 127.0.0.1
```

Monitors/Revokers client image
```bash
docker run --rm -it --network "host" -v $PWD/scripts/monitors:/tmp/crypto glcr.gicp.es/spirs/tee-integration:client-mon -r -C /tmp/crypto/usr1.crt -K /tmp/crypto/usr1.key -H 127.0.0.1
```

## Tests
We have developed several test cases using pytest to verify the correct functionality
of the API server and clients. The code can be found in the dorectory `host/tests`
```bash
python3 host/tests/run_tests.py -h
python3 host/tests/run_tests.py --cov
```
> pandas package is required to process the output of the commands executed
