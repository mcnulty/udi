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
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=udi");
    println!("cargo:rustc-link-search=native=../libudi-c/target/debug");

    let bindings = bindgen::Builder::default().no_unstable_rust()
                                              .header("../libudi-c/src/libudi.h")
                                              .generate()
                                              .expect("Unable to generate libudi bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("udi_ffi.rs"))
            .expect("Could not write udi_ffs bindings");
}
