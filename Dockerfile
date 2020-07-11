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
    rustup default nightly-2020-04-07 && \
    rustup target add wasm32-unknown-unknown --toolchain nightly-2020-04-07 && \
    rustup run nightly-2020-04-07 cargo --version && \
    rustup run nightly-2020-04-07 cargo install -f cargo && \
    rustup run nightly-2020-04-07 cargo --version

ENV RUSTC_BOOTSTRAP=1

ENV SGX_DEBUG=0
ENV SGX_MODE=HW

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

ARG PSW_PKG_VERSION=2.9.101.2-bionic1
RUN apt-get install -y dkms gnupg2 apt-transport-https software-properties-common curl && \
    curl -fsSL  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    add-apt-repository "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" && \
    apt-get update && \
    apt-get install -y \
        libsgx-aesm-launch-plugin=$PSW_PKG_VERSION \
        libsgx-enclave-common=$PSW_PKG_VERSION \
        libsgx-epid=$PSW_PKG_VERSION \
        libsgx-launch=$PSW_PKG_VERSION \
        libsgx-quote-ex=$PSW_PKG_VERSION \
        libsgx-uae-service=$PSW_PKG_VERSION \
        libsgx-urts=$PSW_PKG_VERSION

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
