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

use udi::{Process, ProcessConfig, Thread, Error, ErrorKind, Result, UserData};

pub struct udi_thread_struct {
    handle: Arc<Mutex<Thread>>,
    next: *const udi_thread_struct
}

pub struct udi_process_struct {
    handle: Arc<Mutex<Process>>,
    thr: *const udi_thread_struct
}

const UDI_ERROR_LIBRARY: libc::c_int = 0;
const UDI_ERROR_REQUEST: libc::c_int = 1;
const UDI_ERROR_NONE: libc::c_int = 2;

#[repr(C)]
pub struct udi_error_struct {
    pub code: libc::c_int,
    pub msg: *const libc::c_schar,
}

trait UnsafeFrom<T> {
    unsafe fn from(_: T) -> Self;
}

impl UnsafeFrom<Result<()>> for udi_error_struct {
    unsafe fn from(result: Result<()>) -> udi_error_struct {
        match result {
            Ok(_) => udi_error_struct{ code: UDI_ERROR_NONE, msg: std::ptr::null() },
            Err(e) => match *e.kind() {
                ErrorKind::Request(ref msg) => {
                    udi_error_struct{ code: UDI_ERROR_REQUEST, msg: to_error_msg(&msg) }
                },
                _ => {
                    let msg = format!("{}", e);
                    udi_error_struct{ code: UDI_ERROR_LIBRARY, msg: to_error_msg(&msg) }
                }
            }
        }
    }
}

impl UnsafeFrom<Error> for udi_error_struct {
    unsafe fn from(e: Error) -> udi_error_struct {
        match *e.kind() {
            ErrorKind::Request(ref msg) => {
                udi_error_struct{ code: UDI_ERROR_REQUEST, msg: to_error_msg(&msg) }
            },
            _ => {
                let msg = format!("{}", e);
                udi_error_struct{ code: UDI_ERROR_LIBRARY, msg: to_error_msg(&msg) }
            }
        }
    }
}

impl<'a> UnsafeFrom<std::sync::PoisonError<std::sync::MutexGuard<'a, Process>>> for udi_error_struct {
    unsafe fn from(_: std::sync::PoisonError<std::sync::MutexGuard<'a, Process>>) -> udi_error_struct {
        udi_error_struct{ code: UDI_ERROR_LIBRARY, msg: to_error_msg("lock failed") }
    }
}

impl<'a> UnsafeFrom<std::sync::PoisonError<std::sync::MutexGuard<'a, Thread>>> for udi_error_struct {
    unsafe fn from(_: std::sync::PoisonError<std::sync::MutexGuard<'a, Thread>>) -> udi_error_struct {
        udi_error_struct{ code: UDI_ERROR_LIBRARY, msg: to_error_msg("lock failed") }
    }
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

macro_rules! try_err {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(err) => return UnsafeFrom::from(err)
    });
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
                                        process: *mut *const udi_process_struct)
    -> udi_error_struct
{
    if executable.is_null() {
        *process = std::ptr::null();
        return udi_error_struct{
            code: UDI_ERROR_REQUEST,
            msg: to_error_msg("Executable cannot be null")
        };
    }

    if argv.is_null() {
        *process = std::ptr::null();
        return udi_error_struct{
            code: UDI_ERROR_REQUEST,
            msg: to_error_msg("Argument array cannot be null")
        };
    }

    if config.is_null() {
        *process = std::ptr::null();
        return udi_error_struct{
            code: UDI_ERROR_REQUEST,
            msg: to_error_msg("Process config cannot be null")
        };
    }

    let exec_str = match CStr::from_ptr(executable).to_str() {
        Ok(val) => val,
        Err(_) => {
            *process = std::ptr::null();
            return udi_error_struct{
                code: UDI_ERROR_REQUEST,
                msg: to_error_msg("Executable is not a valid UTF-8 string")
            };
        }
    };

    let argv_vec = match to_vec(argv) {
        Ok(val) => val,
        Err(msg) => {
            *process = std::ptr::null();
            return udi_error_struct{
                code: UDI_ERROR_REQUEST,
                msg: msg
            };
        }
    };

    let envp_vec;
    if envp != std::ptr::null() {
        envp_vec = match to_vec(envp) {
            Ok(val) => val,
            Err(msg) => {
                *process = std::ptr::null();
                return udi_error_struct{
                    code: UDI_ERROR_REQUEST,
                    msg
                };
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
                *process = std::ptr::null();
                return udi_error_struct{
                    code: UDI_ERROR_REQUEST,
                    msg: to_error_msg("Process config root dir is not a valid UTF-8 string")
                };
            }
        };
    }else{
        root_dir_str = None;
    }

    let proc_config = ProcessConfig{ root_dir: root_dir_str };

    match udi::create_process(exec_str, &argv_vec, &envp_vec, &proc_config) {
        Ok(p) => {

            let thread_ptr;
            {
                let udi_process = try_err!(p.lock());
                thread_ptr = Box::new(udi_thread_struct {
                    handle: udi_process.get_initial_thread(),
                    next: std::ptr::null()
                });
            }

            let process_ptr = Box::new(udi_process_struct{
                handle: p,
                thr: Box::into_raw(thread_ptr)
            });
            *process = Box::into_raw(process_ptr);

            udi_error_struct{
                code: UDI_ERROR_NONE,
                msg: std::ptr::null()
            }
        },
        Err(e) => {
            *process = std::ptr::null();

            UnsafeFrom::from(e)
        }
    }
}

unsafe fn to_vec(arr: *const *const libc::c_schar)
    -> std::result::Result<Vec<String>, *const libc::c_schar> {

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
pub unsafe extern "C"
fn free_process(process: *const udi_process_struct) {

    let mut thr_ptr = (*process).thr;
    while thr_ptr != std::ptr::null() {
        let next_ptr = (*thr_ptr).next;

        drop(Box::from_raw(thr_ptr as *mut udi_thread_struct));

        thr_ptr = next_ptr;
    }

    let process_ptr = Box::from_raw(process as *mut udi_process_struct);
    drop(process_ptr);
}

#[no_mangle]
pub unsafe extern "C"
fn continue_process(process_wrapper: *const udi_process_struct) -> udi_error_struct {
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.continue_process())
}

#[no_mangle]
pub unsafe extern "C"
fn refresh_state(process_wrapper: *const udi_process_struct) -> udi_error_struct {
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.refresh_state())
}

#[derive(Debug)]
struct CUserData {
    pub ptr: *const libc::c_void
}

impl UserData for CUserData {}

#[no_mangle]
pub unsafe extern "C"
fn set_user_data(process_wrapper: *const udi_process_struct, data: *const libc::c_void)
    -> udi_error_struct
{
    let data_ptr = Box::new(CUserData{ ptr: data });

    let mut process = try_err!((*process_wrapper).handle.lock());

    process.set_user_data(data_ptr);

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_user_data(process_wrapper: *const udi_process_struct, data: *mut *const libc::c_void)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    let user_data = process.get_user_data()
        .and_then(|d| d.downcast_ref::<CUserData>())
        .map(|c| c.ptr)
        .unwrap_or(std::ptr::null());

    *data = user_data;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_proc_pid(process_wrapper: *const udi_process_struct, output: *mut libc::uint32_t)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = process.get_pid();

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_proc_architecture(process_wrapper: *const udi_process_struct, output: *mut libc::uint32_t)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = process.get_architecture() as u32;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_multithread_capable(process_wrapper: *const udi_process_struct, output: *mut libc::int32_t)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = process.is_multithread_capable() as i32;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_initial_thread(process_wrapper: *const udi_process_struct,
                      output: *mut *const udi_thread_struct)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = (*process_wrapper).thr;

    drop(process);

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn is_running(process_wrapper: *const udi_process_struct, output: *mut libc::int32_t)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = process.is_running() as i32;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn is_terminated(process_wrapper: *const udi_process_struct, output: *mut libc::int32_t)
    -> udi_error_struct
{
    let process = try_err!((*process_wrapper).handle.lock());

    *output = process.is_terminated() as i32;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn set_thread_user_data(thr_wrapper: *const udi_thread_struct, data: *const libc::c_void)
    -> udi_error_struct
{
    let user_data = Box::new(CUserData{ ptr: data });

    let mut thr = try_err!((*thr_wrapper).handle.lock());

    thr.set_user_data(user_data);

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_thread_user_data(thr_wrapper: *const udi_thread_struct, data: *mut *const libc::c_void)
    -> udi_error_struct
{
    let mut thr = try_err!((*thr_wrapper).handle.lock());

    let user_data = thr.get_user_data()
        .and_then(|d| d.downcast_ref::<CUserData>())
        .map(|c| c.ptr)
        .unwrap_or(std::ptr::null());

    *data = user_data;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_tid(thr_wrapper: *const udi_thread_struct, output: *mut libc::uint64_t)
    -> udi_error_struct
{
    let thr = try_err!((*thr_wrapper).handle.lock());

    *output = thr.get_tid();

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_state(thr_wrapper: *const udi_thread_struct, output: *mut libc::uint32_t)
    -> udi_error_struct
{
    let thr = try_err!((*thr_wrapper).handle.lock());

    *output = thr.get_state() as u32;

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn get_next_thread(proc_wrapper: *const udi_process_struct,
                   thr_wrapper: *const udi_thread_struct,
                   output: *mut *const udi_thread_struct)
    -> udi_error_struct
{
    let process = try_err!((*proc_wrapper).handle.lock());

    *output = (*thr_wrapper).next;

    drop(process);

    UnsafeFrom::from(Ok(()))
}

#[no_mangle]
pub unsafe extern "C"
fn resume_thread(thr_wrapper: *const udi_thread_struct)
    -> udi_error_struct
{
    let mut thr = try_err!((*thr_wrapper).handle.lock());

    UnsafeFrom::from(thr.resume())
}

#[no_mangle]
pub unsafe extern "C"
fn suspend_thread(thr_wrapper: *const udi_thread_struct)
    -> udi_error_struct
{
    let mut thr = try_err!((*thr_wrapper).handle.lock());

    UnsafeFrom::from(thr.suspend())
}

#[no_mangle]
pub unsafe extern "C"
fn set_single_step(thr_wrapper: *const udi_thread_struct, enable: libc::c_int)
    -> udi_error_struct
{
    let mut thr = try_err!((*thr_wrapper).handle.lock());

    UnsafeFrom::from(thr.set_single_step(enable != 0))
}

#[no_mangle]
pub unsafe extern "C"
fn get_single_step(thr_wrapper: *const udi_thread_struct, output: *mut libc::int32_t)
    -> udi_error_struct
{
    let thr = try_err!((*thr_wrapper).handle.lock());

    *output = thr.get_single_step() as i32;

    UnsafeFrom::from(Ok(()))
}


#[no_mangle]
pub unsafe extern "C"
fn create_breakpoint(process_wrapper: *const udi_process_struct, addr: libc::uint64_t)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.create_breakpoint(addr))
}

#[no_mangle]
pub unsafe extern "C"
fn install_breakpoint(process_wrapper: *const udi_process_struct, addr: libc::uint64_t)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.install_breakpoint(addr))
}

#[no_mangle]
pub unsafe extern "C"
fn remove_breakpoint(process_wrapper: *const udi_process_struct, addr: libc::uint64_t)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.remove_breakpoint(addr))
}

#[no_mangle]
pub unsafe extern "C"
fn delete_breakpoint(process_wrapper: *const udi_process_struct, addr: libc::uint64_t)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    UnsafeFrom::from(process.delete_breakpoint(addr))
}

#[no_mangle]
pub unsafe extern "C"
fn mem_access(process_wrapper: *const udi_process_struct,
              write: libc::c_int,
              value: *const libc::uint8_t,
              size: libc::uint32_t,
              addr: libc::uint64_t)
    -> udi_error_struct
{
    let mut process = try_err!((*process_wrapper).handle.lock());

    if write != 0 {
        let src = std::slice::from_raw_parts(value, size as usize);
        UnsafeFrom::from(process.write_mem(src, addr))
    } else {
        let data = try_err!(process.read_mem(size, addr));
        let dst = value as *mut libc::uint8_t;
        let src = &data[0] as *const libc::uint8_t;
        libc::memcpy(dst as *mut libc::c_void, src as *const libc::c_void, size as usize);
        UnsafeFrom::from(Ok(()))
    }
}
