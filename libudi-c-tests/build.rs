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
extern crate native_file_tests;

use std::env;
use std::path::PathBuf;
use std::process::Command;

const NATIVE_FILE_TESTS_URL: &'static str =
    "https://github.com/udidb/native-file-tests/releases/download/v0.1.0/native-file-tests-0.1.0.zip";

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
    let manifest_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let local_zip = manifest_path.join("native-file-tests.zip");

    if !local_zip.exists() {
        Command::new("curl").arg("-sSfL")
                            .arg("-o")
                            .arg(local_zip.to_str().unwrap())
                            .arg(NATIVE_FILE_TESTS_URL)
                            .spawn()
                            .expect("Failed to start download of native file tests zip")
                            .wait()
                            .expect("Failed to download native file tests zip");
    }

    native_file_tests::setup(&out_path, &local_zip);
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    generate_bindings(&out_path);
    setup_native_file_tests(&out_path);
}
