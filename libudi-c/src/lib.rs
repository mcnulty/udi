//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]
#![allow(non_camel_case_types)]

extern crate libc;
extern crate udi;

use std::sync::{Mutex,Arc};
use std::ffi::{CStr, CString};

use udi::{Process, ProcessConfig, UdiError};

//const UDI_DEBUG_ENV: &'static str = "UDI_DEBUG";

pub struct udi_process_struct {
    handle: Arc<Mutex<Process>>,
}

const UDI_ERROR_LIBRARY: libc::c_int = 0;
const UDI_ERROR_REQUEST: libc::c_int = 1;
const UDI_ERROR_NONE: libc::c_int = 2;

const LOCK_FAILED_MSG: &'static str = "Failed to lock access to process";

#[repr(C)]
pub struct udi_error_struct {
    code: libc::c_int,
    msg: *const libc::c_schar,
}

unsafe fn from_libudi_result(input: Result<(), UdiError>) -> udi_error_struct {
    match input {
        Ok(_) => udi_error_struct{ code: UDI_ERROR_NONE, msg: std::ptr::null() },
        Err(e) => match e {
            UdiError::Library(msg) => {
                udi_error_struct{ code: UDI_ERROR_LIBRARY, msg: to_error_msg(&msg) }
            },
            UdiError::Request(msg) => {
                udi_error_struct{ code: UDI_ERROR_REQUEST, msg: to_error_msg(&msg) }
            },
        },
    }
}

#[repr(C)]
pub struct udi_proc_config_struct {
    root_dir: *const libc::c_schar,
}

#[no_mangle]
pub unsafe extern "C" fn create_process(executable: *const libc::c_schar,
                                        argv: *const *const libc::c_schar,
                                        envp: *const *const libc::c_schar,
                                        config: *const udi_proc_config_struct,
                                        error: *mut udi_error_struct) -> *const udi_process_struct
{
    if executable.is_null() {
        (*error).code = UDI_ERROR_REQUEST;
        (*error).msg = to_error_msg("Executable cannot be null");
        return std::ptr::null();
    }

    if argv.is_null() {
        (*error).code = UDI_ERROR_REQUEST;
        (*error).msg = to_error_msg("Argument array cannot be null");
        return std::ptr::null();
    }

    if config.is_null() {
        (*error).code = UDI_ERROR_REQUEST;
        (*error).msg = to_error_msg("Process config cannot be null");
        return std::ptr::null();
    }

    let exec_str = match CStr::from_ptr(executable).to_str() {
        Ok(val) => val,
        Err(_) => {
            (*error).code = UDI_ERROR_REQUEST;
            (*error).msg = to_error_msg("Executable is not a valid UTF-8 string");
            return std::ptr::null();
        }
    };

    let argv_vec = match to_vec(argv) {
        Ok(val) => val,
        Err(msg) => {
            (*error).code = UDI_ERROR_REQUEST;
            (*error).msg = msg;
            return std::ptr::null();
        }
    };

    let envp_vec;
    if envp != std::ptr::null() {
        envp_vec = match to_vec(envp) {
            Ok(val) => val,
            Err(msg) => {
                (*error).code = UDI_ERROR_REQUEST;
                (*error).msg = msg;
                return std::ptr::null();
            }
        };
    }else{
        envp_vec = vec![];
    }

    let root_dir_str;
    if (*config).root_dir != std::ptr::null() {
        root_dir_str = match CStr::from_ptr((*config).root_dir).to_str() {
            Ok(val) => Some(val.to_owned()),
            Err(_) => {
                (*error).code = UDI_ERROR_REQUEST;
                (*error).msg = to_error_msg("Process config root dir is not a valid UTF-8 string");
                return std::ptr::null();
            }
        };
    }else{
        root_dir_str = None;
    }

    let proc_config = ProcessConfig{ root_dir: root_dir_str };

    match udi::create_process(exec_str, &argv_vec, &envp_vec, &proc_config) {
        Ok(process) => {
            (*error).code = UDI_ERROR_NONE;
            (*error).msg = std::ptr::null();

            let process_ptr = Box::new(udi_process_struct{ handle: process });
            Box::into_raw(process_ptr)
        },
        Err(e) => {
            match e {
                UdiError::Library(msg) => {
                    (*error).code = UDI_ERROR_LIBRARY;
                    (*error).msg = to_error_msg(&msg);
                },
                UdiError::Request(msg) => {
                    (*error).code = UDI_ERROR_REQUEST;
                    (*error).msg = to_error_msg(&msg);
                }
            }

            std::ptr::null()
        }
    }
}

unsafe fn to_vec(arr: *const *const libc::c_schar) -> Result<Vec<String>, *const libc::c_schar> {

    let mut x = 0;

    let mut output: Vec<String> = vec![];
    while arr.offset(x) != std::ptr::null() {
        let elem = arr.offset(x) as *const libc::c_schar;

        let elem_str = match CStr::from_ptr(elem).to_str() {
            Ok(val) => val.to_owned(),
            Err(_) => return Err(to_error_msg("Invalid string in specified array")),
        };

        output.push(elem_str);

        x = x + 1;
    }

    Ok(output)
}

#[no_mangle]
pub unsafe extern "C" fn free_process(process: *const udi_process_struct) {
    let process_ptr = Box::from_raw(process as *mut udi_process_struct);
    drop(process_ptr);
}

#[no_mangle]
pub unsafe extern "C"
fn continue_process(process_wrapper: *const udi_process_struct) -> udi_error_struct {
    let mut process = match (*process_wrapper).handle.lock() {
        Ok(val) => val,
        Err(_) => {
            return from_libudi_result(Err(UdiError::Library(LOCK_FAILED_MSG.to_owned())));
        }
    };

    let result = process.continue_process();

    from_libudi_result(result)
}

unsafe fn to_error_msg(msg: &str) -> *const libc::c_schar {
    let cstr = match CString::new(msg) {
        Ok(val) => val,
        Err(_) => return std::ptr::null(),
    };

    let len = cstr.to_bytes_with_nul().len();
    let output = libc::malloc(len);
    libc::memcpy(output, cstr.as_ptr() as *const libc::c_void, len);
    output as *const libc::c_schar
}
