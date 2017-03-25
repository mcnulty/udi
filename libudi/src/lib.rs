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
extern crate serde;
#[macro_use]
extern crate serde_derive;

use std::fs;

pub mod protocol;
pub mod error;
mod create;
mod process;
mod thread;

pub use error::UdiError;
pub use create::create_process;
pub use create::ProcessConfig;

#[derive(Debug)]
enum Architecture {
    X32,
    X64
}

fn to_arch(arch_num: u32) -> Result<Architecture, UdiError> {
    match arch_num {
        0 => Ok(Architecture::X32),
        1 => Ok(Architecture::X64),
        _ => Err(UdiError::Library(format!("Unknown architecture number: {}", arch_num)))
    }
}

#[derive(Debug)]
pub struct Process {
    pid: u32,
    request_file: fs::File,
    response_file: fs::File,
    events_file: fs::File,
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
enum ThreadState {
    Running,
//    Suspended
}

#[derive(Debug)]
pub struct Thread {
    initial: bool,
    tid: u64,
    request_file: fs::File,
    response_file: fs::File,
    single_step: bool,
    state: ThreadState,
    user_data: *const libc::c_void
}

#[cfg(test)]
mod tests {
}
