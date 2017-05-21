//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate bindgen;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const NATIVE_FILE_TESTS_URL: &'static str =
    "https://dl.bintray.com/mcnulty/generic/native-file-tests-0.2.0.zip";

fn generate_bindings(out_path: &PathBuf) {
    println!("cargo:rustc-link-lib=udi");
    println!("cargo:rustc-link-search=native=../libudi-c/target/debug");

    let bindings = bindgen::Builder::default().no_unstable_rust()
                                              .header("../libudi-c/src/libudi.h")
                                              .generate()
                                              .expect("Unable to generate libudi bindings");

    bindings.write_to_file(out_path.join("udi_ffi.rs"))
            .expect("Could not write udi_ffs bindings");
}

fn setup_native_file_tests(out_path: &PathBuf) {
    let dest_path = out_path.join("native-file-tests.zip");

    Command::new("curl").arg("-o")
                        .arg(dest_path.to_str().unwrap())
                        .arg(NATIVE_FILE_TESTS_URL)
                        .spawn()
                        .expect("Failed to download native file tests zip");

    let dest_dir = out_path.join("native-file-tests");
    Command::new("unzip").arg("-j")
                         .arg(dest_path.to_str().unwrap())
                         .arg("-d")
                         .arg(dest_dir.to_str().unwrap())
                         .spawn()
                         .expect("Failed to extract native file tests zip");

    let simple_path = dest_dir.join("simple-debug-noopt-dynamic.cd52194667df0781720ff834a56df134fef7fb51");

    let mod_file_path = out_path.join("native_file_tests.rs");
    let mut mod_file = File::create(&mod_file_path).unwrap();

    let mod_file_content = format!("
    pub const SIMPLE_EXEC_PATH: &'static str = \"{}\";
    ",
    simple_path.to_str().unwrap());

    mod_file.write_all(&mod_file_content.into_bytes())
            .expect("Failed to write native file tests module");
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    generate_bindings(&out_path);
    setup_native_file_tests(&out_path);
}
