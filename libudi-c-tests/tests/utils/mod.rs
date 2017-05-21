//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

use super::udi_ffi;

use std::ffi::CStr;

pub unsafe fn assert_no_error(error: &udi_ffi::udi_error) {
    let errmsg = if error.msg != ::std::ptr::null() {
        CStr::from_ptr(error.msg).to_str().unwrap()
    } else {
        ""
    };

    assert!(error.code == udi_ffi::udi_error_e::UDI_ERROR_NONE, "{:?}", errmsg);
}

pub unsafe fn wait_for_exit(process: *mut udi_ffi::udi_process,
                            thr: *mut udi_ffi::udi_thread,
                            expected_status: i32) {

    let mut procs = vec![ process ];

    let mut events = udi_ffi::wait_for_events(procs.as_mut_ptr(), 1);
    assert!(events != ::std::ptr::null_mut());
    assert!((*events).process == process);
    assert!((*events).thr == thr);
    assert!((*events).event_type == udi_ffi::udi_event_type_e::UDI_EVENT_PROCESS_EXIT);
    assert!((*events).next_event == ::std::ptr::null_mut());

    let proc_exit = (*events).event_data as *const udi_ffi::udi_event_process_exit;
    assert!((*proc_exit).exit_code == expected_status);

    udi_ffi::free_event_list(events);

    let mut error = udi_ffi::continue_process(process);
    assert_no_error(&error);

    events = udi_ffi::wait_for_events(procs.as_mut_ptr(), 1);
    assert!(events != ::std::ptr::null_mut());
    assert!((*events).process == process);
    assert!((*events).thr == thr);
    assert!((*events).event_type == udi_ffi::udi_event_type_e::UDI_EVENT_PROCESS_CLEANUP);
    assert!((*events).next_event == ::std::ptr::null_mut());

    udi_ffi::free_event_list(events);

    udi_ffi::free_process(process);
}
