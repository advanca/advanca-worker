# Advanca Worker

[![rust-badge](https://github.com/advanca/advanca-worker/workflows/Rust/badge.svg)](https://github.com/advanca/advanca-worker/actions?query=workflow%3ARust)

This repository contains the source code of Advanca Worker. See [advanca/advanca](https://github.com/advanca/advanca) for more information.

Before you start, make sure you clone the repository recursively.

```shell
git clone --recursive https://github.com/advanca/advanca-worker.git
```

## Requirements

To build and run the project, there are some requirements listed below. You may choose to install some of them according to your need.

|                                                     |       Build        |  Run (Simulation)  |   Run (Hardware)   |
|-----------------------------------------------------|:------------------:|:------------------:|:------------------:|
| [Rust Toolchain](#rust-toolchain)                   | :heavy_plus_sign:  | :heavy_minus_sign: | :heavy_minus_sign: |
| [System Packages](#system-packages)                 | :heavy_plus_sign:  | :heavy_plus_sign:  | :heavy_plus_sign:  |
| [Intel SGX Linux SDK](#intel-sgx-linux-sdk-and-psw) | :heavy_plus_sign:  | :heavy_plus_sign:  | :heavy_plus_sign:  |
| [Intel SGX Linux Driver](#intel-sgx-linux-driver)   | :heavy_plus_sign:  | :heavy_minus_sign: | :heavy_plus_sign:  |
| [Intel SGX Linux PSW](#intel-sgx-linux-sdk-and-psw) | :heavy_minus_sign: | :heavy_minus_sign: | :heavy_plus_sign:  |
| [SGX Hardware](#sgx-hardware)                       | :heavy_minus_sign: | :heavy_minus_sign: | :heavy_plus_sign:  |

**Notes**

* :heavy_plus_sign:  Required
* :heavy_plus_sign:  Not required

### Rust Toolchain

Install Rust toolchain through [**rustup**](https://rustup.rs/) and complete the installation following the prompted instructions from command line.

```bash
curl https://sh.rustup.rs -sSf | sh
```

The repository contains a [`rust-toolchain`](rust-toolchain) that specifies a different version from the default toolchain installation.

To install the required version, go to the directory and run:

```bash
cd advanca-worker/
# This installs WASM, but it also triggers an installation of the said version in `rust-toolchain`.
rustup target add wasm32-unknown-unknown
```

### System Packages

The project is developmend on **Ubuntu 18.04**. You may need to install the following packages:

```shell
sudo apt-get update
sudo apt-get install -y make build-essential cmake protobuf-compiler golang automake libtool libssl-dev
```

> For other Linux distributions, there are no instructions available yet. However, you may install similar packages and get them working with the project.

### Intel SGX for Linux

The project relies on the following SGX dependencies on specific versions, which work best with [Rust SGX SDK v1.1.2](https://github.com/apache/incubator-teaclave-sgx-sdk/tree/v1.1.2#v112):

* **Intel SGX Linux Driver v2.6.0** (out-of-tree version, not [DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver))
* **Intel SGX Linux SDK and PSW v2.9.1**

#### Intel SGX Linux Driver

Follow the [offical install instructions](https://github.com/intel/linux-sgx-driver/tree/sgx_driver_2.6#build-and-install-the-intelr-sgx-driver) to build and install **Intel SGX Linux Driver v2.6.0**.

#### Intel SGX Linux SDK and PSW

You can build SDK and PSW installers from the source code following its [offical build instructions](https://github.com/intel/linux-sgx/tree/sgx_2.9.1#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package).

Alternatively, you can obtain the ready-to-use installers from [Intel's website](https://download.01.org/intel-sgx/sgx-linux/2.9.1/).

Once you have the installers, follow these guides for installation:

* [Install Intel SGX SDK](https://github.com/intel/linux-sgx/tree/sgx_2.9.1#install-the-intelr-sgx-sdk)
* [Install Intel SGX PSW](https://github.com/intel/linux-sgx/tree/sgx_2.9.1#install-the-intelr-sgx-psw-1)

### SGX Hardware

A [community-maintained list](https://github.com/ayeks/SGX-hardware) of SGX-capable machines is available. It is only need when running the project in hardware mode.

## Build

Add this to your shell profile or run it everytime before you build.

```bash
# The script path may differ on your machine. It's located inside the SDK installtion destination
source /opt/intel/sgxsdk/environment
```

You may also use the following environment variables to set the build options.

| Environment Variable | Default |           Accepted Values           |                                                Description                                                 |
|:--------------------:|:-------:|:-----------------------------------:|:----------------------------------------------------------------------------------------------------------:|
|     `SGX_DEBUG`      |   `0`   |  <ul><li>`0`</li><li>`1`</li></ul>  | If the Debug mode is enabled (`1`) or not (`0`). It also affects cargo build targets in the subdirectories |
|      `SGX_MODE`      |  `HW`   | <ul><li>`HW`</li><li>`SW`</li></ul> |                     If the built artifact is for hardware (`HW`) or simulation (`SW`)                      |

### Build in Simulation Mode

```bash
# set the environment variable SGX_MODE=SW
SGX_MODE=SW make
# or with DEBUG symbols
SGX_MODE=SW SGX_DEBUG=1 make
```

### Build in Hardware Mode

```bash
# implicilty ask for a hardware build
make
# or set the environment variable SGX_MODE=HW
SGX_MODE=HW make
# or with DEBUG symbols
SGX_MODE=HW SGX_DEBUG=1 make
```

### Built Artifacts

The built artifacts can be found under `./bin` directory.

* `advanca-client`: The client which executes the demo introduced in [github.com/advanca/advanca](https://github.com/advanca/advanca).
* `advanca-worker`: The worker that loads the `enclave.signed.so`. See more at [github.com/advanca/advanca](https://github.com/advanca/advanca).
* `enclave.signed.so`: The signed enclave dynamic library.

## Run

The Advanca Worker needs to work with [`Advanca Node`](https://github.com/advanca/advanca-node). See the umbrella project [github.com/advanca/advanca](https://github.com/advanca/advanca) for more information.

## License

This repository is licensed under [`GPL 3.0`](LICENSE) except the code in these directories:

- [`protos/`](protos): Licensed under [`Apache-2.0`](protos/LICENSE)
- [`enclave/`](enclave): Licensed under [`Apache-2.0`](enclave/LICENSE)
