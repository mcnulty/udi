//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate native_file_tests;

use std::env;
use std::path::PathBuf;

const NATIVE_FILE_TESTS_URL: &'static str =
    "https://dl.bintray.com/mcnulty/generic/native-file-tests-0.2.0.zip";

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    native_file_tests::setup(&out_path, NATIVE_FILE_TESTS_URL);
}
