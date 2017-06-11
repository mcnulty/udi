//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]
#![allow(unused)]

mod udi_ffi;
mod native_file_tests;
mod utils;

#[test]
fn breakpoint() {
    unsafe {
        let config = udi_ffi::udi_proc_config{ root_dir: ptr::null() };

        let binary_path = CString::new(native_file_tests::SIMPLE_EXEC_PATH).unwrap();

        let argv = vec![ ptr::null() ];

        let mut error = udi_ffi::udi_error{
            code: udi_ffi::udi_error_e::UDI_ERROR_NONE,
            msg: ptr::null()
        };

        let process = udi_ffi::create_process(binary_path.as_ptr(),
                                              argv.as_ptr(),
                                              ptr::null(),
                                              &config as *const udi_ffi::udi_proc_config,
                                              &mut error as *mut udi_ffi::udi_error);
        assert!(process != ptr::null_mut());
        utils::assert_no_error(&error);

        assert!(udi_ffi::get_multithread_capable(process) == 0);

        let thread = udi_ffi::get_initial_thread(process);
        assert!(thread != ptr::null_mut());

        error = udi_ffi::create_breakpoint(process, native_file_tests::SIMPLE_FUNCTION1);
        utils::assert_no_error(&error);

        error = udi_ffi::install_breakpoint(process, native_file_tests::SIMPLE_FUNCTION1);
        utils::assert_no_error(&error);

        error = udi_ffi::continue_process(process);
        utils::assert_no_error(&error);

        wait_for_breakpoint(thr, TEST_FUNCTION);

        let pc: u64 = 0;
        error = udi_ffi::get_pc(thr, &pc);
        result = get_pc(thr, &pc);
        assert_no_error(proc, result);

        stringstream msg;
        msg << "Actual: "
            << std::hex
            << pc
            << std::dec
            << " Expected: "
            << std::hex
            << TEST_FUNCTION
            << std::dec;
        test_assert_msg(msg.str().c_str(), pc == TEST_FUNCTION);

        error = continue_process(process);
        utils::assert_no_error(&error);

        wait_for_exit(thr, EXIT_FAILURE);
    }
}

