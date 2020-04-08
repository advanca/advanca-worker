# Advanca Worker

This repository contains the source code of Advanca Worker.

See [advanca/advanca](https://github.com/advanca/advanca) for more information.

## Requirements

The project is developmend on Ubuntu 18.04. You may need to install the following packages:

```
sudo apt-get update
sudo apt-get install -y make build-essential cmake protobuf-compiler golang automake libtool
```
The repository contains submodule, make sure you clone the code recursively.

```
git clone --recursive https://github.com/advanca/advanca-worker.git
```

## Build

Install the Intel(R) SGX SDK v2.9.100.2 (the version supported by rust-sgx-sdk v1.1.1).

You can download the sdk installer `sgx_linux_x64_sdk_2.9.100.2.bin` directly from [here](https://download.01.org/intel-sgx/sgx-linux/2.9/distro/) or manually [build one](https://github.com/intel/linux-sgx/tree/sgx_2.9#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package).

```console
# For ubuntu 18.04
$ curl -sO https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.100.2.bin

$ chmod +x sgx_linux_x64_sdk_2.9.100.2.bin

$ sudo ./sgx_linux_x64_sdk_2.9.100.2.bin
Do you want to install in current directory? [yes/no] : no
Please input the directory which you want to install in : /opt/intel
...
```

Add this to your shell profile or run it everytime before you build.

```
source /opt/intel/sgxsdk/environment
```

Install Rust.

> Note the version specified by [`rust-toolchain`](rust-toolchain) will be used for this repository.

```bash
curl https://sh.rustup.rs -sSf | sh
```

Build in simulation mode.

```
export SGX_MODE=SW
export SGX_DEBUG=1
make
```

## Run

As a prerequisite, build and run [`advanca-node`](https://github.com/advanca/advanca-node) first, and ensure its WebSocket RPC port is listening at `127.0.0.1:9944`.

Then in a new terminal, run the client

```
cd bin/
./advanca-client
```

In another new temrinal, run the worker

```
cd bin/
./advanca-worker
```

## License

This repository is licensed under [`GPL 3.0`](LICENSE) except the code in these directories:

- [`protos/`](protos): Licensed under [`Apache-2.0`](protos/LICENSE)
- [`enclave/`](enclave): Licensed under [`Apache-2.0`](enclave/LICENSE)
