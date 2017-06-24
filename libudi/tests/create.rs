//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate udi;

mod native_file_tests;
mod utils;

use udi::UdiError;

#[test]
fn create() {
    if let Err(e) = create_test() {
        panic!(e.to_string());
    }
}

fn create_test() -> Result<(), UdiError> {

    let config = udi::ProcessConfig{ root_dir: None };
    let argv = Vec::new();
    let envp = Vec::new();

    let proc_ref = udi::create_process(native_file_tests::SIMPLE_EXEC_PATH,
                                       &argv,
                                       &envp,
                                       &config)?;

    let thr_ref;
    {
        let mut process = proc_ref.lock()?;

        assert!(!process.is_multithread_capable());

        process.continue_process()?;

        thr_ref = process.get_initial_thread();
    }

    utils::wait_for_exit(&proc_ref, &thr_ref, 0);

    Ok(())
}
