FROM glcr.gicp.es/spirs/tee-integration:optimized AS intermediate
WORKDIR /spirs_tee_sdk
RUN --mount=type=secret,id=gitlab \
    apt update -qq && apt install -y --no-install-recommends --no-install-suggests \
    libssl-dev && apt-get clean -y && rm -rf /var/lib/apt/lists/* && \
    git config --global credential.helper /usr/local/bin/credential-helper && \
    git clone --depth 1 https://gitlab.gicp.es/spirs/tee-integration /tee-integration && \
    git clone --depth 1 https://gitlab.com/spirs_eu/spirs_tee_sdk . && \
    git clone --depth 1 https://gitlab.gicp.es/spirs/libgroupsig.git modules/libgroupsig && \
    git clone --depth 1 https://gitlab.gicp.es/spirs/mondrian.git modules/mondrian && \
    patch -u enclave/CMakeLists.txt -i /patches/cmakelistsenclave.patch && \
    patch -u host/CMakeLists.txt -i /patches/cmakelistshost.patch && \
    patch -u CMakeLists.txt -i /patches/cmakelists.patch && \
    patch -u modules/libgroupsig/src/wrappers/python/pygroupsig/libgroupsig_build.py -i /patches/pygroupsig.patch && \
    cp -r /tee-integration/modules/libgroupsig/tee modules/libgroupsig && \
    cp -r /tee-integration/modules/mondrian/tee modules/mondrian && \
    bash -c \
    "cp /tee-integration/{groupsig,groupsig_import}.cmake . && \
    cp -r /tee-integration/enclave/{gicp,ta_callbacks_gicp.c} enclave/ && \
    cp -r /tee-integration/host/{gicp_api,host_gicp.c} host/" && \
    cp /tee-integration/enclave/include/ta_shared_gicp.h enclave/include/ && \
    cp /tee-integration/enclave/tee_internal_api/include/tee_ta_api_gicp.h enclave/tee_internal_api/include/ && \
    cmake -B build && make -C build && \
    cmake -B build/libgroupsig modules/libgroupsig && \
    mkdir -p crypto && touch crypto/please_use_your_keys && \
    make -C build/libgroupsig && make -C build -j image

FROM ubuntu:22.04 AS final
ENV KEYSTONE_BUILD_DIR=/keystone/build
ENV KEYSTONE_SDK_DIR=/keystone/sdk/build64
ENV RISCV=/keystone/riscv64
ENV RISCV_MUSL=/opt/spirs/riscv64-musl/riscv-musl
ENV PATH=$RISCV/bin:$RISCV_MUSL/bin:$PATH
WORKDIR /spirs_tee_sdk
RUN apt update -qq && apt install -y --no-install-recommends --no-install-suggests \
    make cmake libpixman-1-dev libglib2.0-dev libslirp-dev makeself build-essential \
    file wget unzip rsync bc cpio locales git libssl-dev openssh-client && \
    apt-get clean -y && rm -rf /var/lib/apt/lists/*
COPY --from=intermediate /keystone /keystone
COPY --from=intermediate /opt/spirs /opt/spirs
COPY --from=intermediate /spirs_tee_sdk /spirs_tee_sdk
