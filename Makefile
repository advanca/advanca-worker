# Copyright (C) 2020 ADVANCA PTE. LTD.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# 
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

##### RUST SGX SDK Settings ######

RUST_SGX_SDK=./rust-sgx-sdk

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif


ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## CUSTOM Settings ########

CUSTOM_APP_NAME := advanca-worker
CUSTOM_APP_PATH := ./app
CUSTOM_ENCLAVE_PATH := ./enclave
CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := $(RUST_SGX_SDK)/edl
CUSTOM_COMMON_PATH := $(RUST_SGX_SDK)/common
CUSTOM_CLIENT_NAME := advanca-client
CUSTOM_CLIENT_PATH := ./client

######## EDL Settings ########

Enclave_EDL_Files := $(CUSTOM_ENCLAVE_PATH)/Enclave_t.c $(CUSTOM_ENCLAVE_PATH)/Enclave_t.h $(CUSTOM_APP_PATH)/Enclave_u.c $(CUSTOM_APP_PATH)/Enclave_u.h

######## APP Settings ########

ifeq ($(SGX_DEBUG), 1)
App_Rust_Flags :=
else
App_Rust_Flags := --release
endif
App_SRC_Files := $(shell find $(CUSTOM_APP_PATH)/ -type f -name '*.rs') $(shell find $(CUSTOM_APP_PATH)/ -type f -name 'Cargo.toml')
App_Include_Paths := -I $(CUSTOM_APP_PATH) -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

ifeq ($(SGX_DEBUG), 1)
App_Build_Path := target/debug
else
App_Build_Path := target/release
endif
App_Enclave_u_Object := $(CUSTOM_APP_PATH)/libEnclave_u.a
App_Name := $(CUSTOM_BIN_PATH)/$(CUSTOM_APP_NAME)

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard $(CUSTOM_ENCLAVE_PATH)/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I $(CUSTOM_ENCLAVE_PATH) -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -l$(Service_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tcxx -lsgx_tstdc -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -lsgx_ukey_exchange -lsgx_tkey_exchange -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=enclave/Enclave.lds

RustEnclave_Name := $(CUSTOM_ENCLAVE_PATH)/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

###### Client Settings ######
Client_SRC_Files := $(shell find $(CUSTOM_CLIENT_PATH)/ -type f -name '*.rs') $(shell find $(CUSTOM_CLIENT_PATH)/ -type f -name 'Cargo.toml')
ifeq ($(SGX_DEBUG), 1)
Client_Rust_Flags := 
Client_Build_Path := target/debug
else
Client_Rust_Flags := --release
Client_Build_Path := target/release
endif
Client_Name := $(CUSTOM_BIN_PATH)/$(CUSTOM_CLIENT_NAME)

.PHONY: all
all: $(App_Name) $(Signed_RustEnclave_Name) $(Client_Name)

###### Client Objects #######

$(Client_Name): $(Client_SRC_Files)
	@cd $(CUSTOM_CLIENT_PATH) && cargo build $(Client_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Build_Path)/$(CUSTOM_CLIENT_NAME) ./bin

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) $(CUSTOM_ENCLAVE_PATH)/Enclave.edl
	$(SGX_EDGER8R) --trusted $(CUSTOM_ENCLAVE_PATH)/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir $(CUSTOM_ENCLAVE_PATH)
	$(SGX_EDGER8R) --untrusted $(CUSTOM_ENCLAVE_PATH)/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir $(CUSTOM_APP_PATH)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## App Objects ########

$(CUSTOM_APP_PATH)/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(App_C_Flags) -c $(CUSTOM_APP_PATH)/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(App_Enclave_u_Object): $(CUSTOM_APP_PATH)/Enclave_u.o
	$(AR) rcsD $@ $^
	cp $(App_Enclave_u_Object) $(CUSTOM_LIBRARY_PATH)

$(App_Name): $(App_Enclave_u_Object) $(App_SRC_Files)
	@cd $(CUSTOM_APP_PATH) && SGX_SDK=$(SGX_SDK) cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Build_Path)/$(CUSTOM_APP_NAME) ./bin

######## Enclave Objects ########

$(CUSTOM_ENCLAVE_PATH)/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(CUSTOM_ENCLAVE_PATH)/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave $(CUSTOM_ENCLAVE_PATH)/Enclave_t.o
	@$(CXX) $(CUSTOM_ENCLAVE_PATH)/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(CUSTOM_ENCLAVE_PATH)/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config $(CUSTOM_ENCLAVE_PATH)/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave:
	$(MAKE) -C $(CUSTOM_ENCLAVE_PATH)/


.PHONY: clean
clean:
	@rm -f $(App_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) $(Client_Name) $(CUSTOM_ENCLAVE_PATH)/*_t.* $(CUSTOM_APP_PATH)/*_u.* $(CUSTOM_LIBRARY_PATH)/*.a
	@cd $(CUSTOM_ENCLAVE_PATH) && cargo clean && rm -f Cargo.lock
	@cd $(CUSTOM_APP_PATH) && cargo clean && rm -f Cargo.lock
	@cd $(CUSTOM_CLIENT_PATH) && cargo clean && rm -f Cargo.lock

