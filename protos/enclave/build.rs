// Copyright 2020 ADVANCA PTE. LTD.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use protoc_rust;
use protoc_rust::Customize;
use std::fs;
use std::fs::File;
use std::io::Write;

fn main() {
    let proto_root = "../";
    let proto_out = "src/";
    protoc_rust::run(protoc_rust::Args {
        out_dir: &proto_out,
        input: &["../storage.proto"],
        includes: &[proto_root],
        customize: Customize {
            ..Default::default()
        },
    })
    .expect("protoc");

    add_prelude("src/storage.rs");
}

fn add_prelude(filepath: &str) {
    let old_content = fs::read_to_string(filepath).expect("Could not read file");
    let content_split: Vec<&str> = old_content.split('\n').collect();

    let mut new_content: Vec<String> = vec![];
    // Alter content
    for line in &content_split {
        if line.starts_with("use protobuf::Message") {
            new_content.push("use sgx_tstd::prelude::v1::*;".into());
        }
        new_content.push(line.to_string());
    }

    // Store file
    let mut file = match File::create(filepath) {
        Err(_) => panic!("Could not open {}", filepath),
        Ok(file) => file,
    };
    for i in &new_content {
        writeln!(file, "{}", i).unwrap();
    }
}
