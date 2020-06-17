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

use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = "src/";
    let modules = &[("../protos/storage", "storage")];
    for (dir, package) in modules {
        let out_dir = format!("{}/{}", out_dir, package);
        let files: Vec<_> = walkdir::WalkDir::new(format!("{}", dir))
            .into_iter()
            .filter_map(|p| {
                let dent = p.expect("Error happened when search protos");
                if !dent.file_type().is_file() {
                    return None;
                }
                // rust-protobuf is bad at dealing with path, keep it the same style.
                Some(format!("{}", dent.path().display()).replace('\\', "/"))
            })
            .collect();
        protobuf_build::Builder::new()
            .includes(&["../protos".to_owned()])
            .files(&files)
            .out_dir(&out_dir)
            .generate_no_grpcio();
        for str_path in files {
            let output_path = Path::new(&out_dir);
            let proto_path = Path::new(&str_path);
            let mut mod_filename = proto_path.file_stem().unwrap().to_os_string();
            mod_filename.push(".rs");

            let mod_wrapper_path = output_path.join(&mod_filename);
            add_prelude(&mod_wrapper_path);
        }
    }
}

fn add_prelude(filepath: &Path) {
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
        Err(_) => panic!("Could not open {:?}", filepath),
        Ok(file) => file,
    };
    for i in &new_content {
        writeln!(file, "{}", i).unwrap();
    }
}
