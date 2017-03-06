//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate libc;

use std::string::String;
use std::result::Result;
use std::sync::{Mutex};

type UdiHandle = i32;

enum ThreadState {
    Running,
    Suspended
}

enum Architecture {
    X32,
    X64
} 

struct Thread {
    initial: bool,
    tid: u64,
    request_handle: UdiHandle,
    response_handle: UdiHandle,
    single_step: bool,
    user_data: *const libc::c_void,
    process: Process,
    next_thread: Box<Thread>
}

pub struct Process {
    pid: u32,
    request_handle: UdiHandle,
    response_handle: UdiHandle,
    events_handle: UdiHandle,
    architecture: Architecture,
    protocol_version: u32,
    multithread_capable: bool,
    running: bool,
    terminating: bool,
    terminated: bool,
    user_data: *const libc::c_void,
    threads: Vec<Thread>,
    root_dir: String
}

#[derive(Debug)]
pub enum Error {
    Library(String),
    Request(String)
}

impl Process {
    pub fn continue_process(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct ProcessConfig {
    pub root_dir: String
}

pub fn create_process(executable: &str,
                      argv: &Vec<String>,
                      envp: &Vec<String>,
                      config: &ProcessConfig) -> Result<Mutex<Process>, Error> {

    let mut p = Process {
        pid: 0,
        request_handle: -1,
        response_handle: -1,
        events_handle: -1,
        architecture: Architecture::X32,
        protocol_version: 1,
        multithread_capable: false,
        running: false,
        terminating: false,
        terminated: false,
        user_data: std::ptr::null(),
        threads: vec![],
        root_dir: String::new()
    };
    Ok(Mutex::new(p))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
