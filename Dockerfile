FROM ubuntu:bionic-20200403 as builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates make build-essential cmake protobuf-compiler golang autoconf libtool automake pkg-config libssl-dev

ARG SGX_SDK_URL=https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin
ARG SGX_SDK_BIN=sgx_linux_x64_sdk_2.9.101.2.bin

RUN curl -sO $SGX_SDK_URL && chmod +x $SGX_SDK_BIN && \
    echo -e 'no\n/opt/intel' | ./$SGX_SDK_BIN && \
    curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly-2020-04-07 -y && \
    export PATH=$PATH:$HOME/.cargo/bin && \
    rustup target add wasm32-unknown-unknown
    
ENV SGX_DEBUG=1
ENV SGX_MODE=SW

COPY . /advanca 

WORKDIR /advanca

RUN . $HOME/.cargo/env && \
    . /opt/intel/sgxsdk/environment && \
    make

#=============== worker =======
FROM ubuntu:bionic-20200403 as worker

ARG SOURCE_PATH=/advanca

COPY --from=builder $SOURCE_PATH/bin/advanca-worker /usr/local/bin

# TODO: copy only the dynamic libraries
COPY --from=builder /opt/intel/sgxsdk /opt/intel/sgxsdk

RUN	useradd -m -u 1000 -U -s /bin/sh -d /advanca advanca

COPY --from=builder $SOURCE_PATH/bin/enclave.signed.so /advanca

RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev

WORKDIR /advanca
USER advanca
EXPOSE 12345

ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/opt/intel/sgxsdk/sdk_libs"

ENTRYPOINT ["/usr/local/bin/advanca-worker"]

#============== client ========
FROM ubuntu:bionic-20200403 as client

ARG SOURCE_PATH=/advanca

COPY --from=builder $SOURCE_PATH/bin/advanca-client /usr/local/bin

RUN	useradd -m -u 1000 -U -s /bin/sh -d /advanca advanca

WORKDIR /advanca
USER advanca

ENTRYPOINT ["/usr/local/bin/advanca-client"]