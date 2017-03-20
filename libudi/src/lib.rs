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
extern crate users;
extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod protocol;
pub mod error;

use std::error::Error;
use std::string::String;
use std::result::Result;
use std::sync::Mutex;
use std::path::{Path, PathBuf};
use std::io;
use std::fs;

pub use error::UdiError;

const DEFAULT_UDI_ROOT_DIR: &'static str = "/tmp/udi";
const DEFAULT_UDI_RT_LIB_NAME: &'static str = "libudirt.so";
const UDI_ROOT_DIR_ENV: &'static str = "UDI_ROOT_DIR";
const REQUEST_FILE_NAME: &'static str = "request";
const RESPONSE_FILE_NAME: &'static str = "response";
const EVENTS_FILE_NAME: &'static str = "events";

#[derive(Debug)]
enum ThreadState {
    Running,
    Suspended
}

#[derive(Debug)]
enum Architecture {
    X32,
    X64
} 

#[derive(Debug)]
pub struct Thread {
    initial: bool,
    tid: u64,
    request_file: fs::File,
    response_file: fs::File,
    single_step: bool,
    user_data: *const libc::c_void,
    process: Process,
    next_thread: Box<Thread>
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
pub struct ProcessConfig {
    pub root_dir: Option<String>
}

/// Creates a new UDI-controlled process
pub fn create_process(executable: &str,
                      argv: &Vec<String>,
                      envp: &Vec<String>,
                      config: &ProcessConfig) -> Result<Mutex<Process>, UdiError> {

    let root_dir = config.root_dir.clone().unwrap_or(DEFAULT_UDI_ROOT_DIR.to_owned());

    create_root_udi_filesystem(&root_dir)?;

    let pid = launch_process(executable, argv, envp, &root_dir)?;

    let process = initialize_process(pid, root_dir)?;

    Ok(Mutex::new(process))
}

fn initialize_process(pid: u32, root_dir: String) -> Result<Process, UdiError> {

    let mut request_path_buf = PathBuf::from(&root_dir);
    request_path_buf.push(pid.to_string());
    request_path_buf.push(REQUEST_FILE_NAME);
    let request_path = request_path_buf.as_path();

    let mut response_path_buf = PathBuf::from(&root_dir);
    response_path_buf.push(pid.to_string());
    response_path_buf.push(RESPONSE_FILE_NAME);
    let response_path = response_path_buf.as_path();

    let mut event_path_buf = PathBuf::from(&root_dir);
    event_path_buf.push(pid.to_string());
    event_path_buf.push(EVENTS_FILE_NAME);
    let event_path = event_path_buf.as_path();

    // poll for change in root UDI filesystem
    // TODO use notify crate for this
    let mut event_file_exists = false;
    while !event_file_exists {
        match fs::metadata(event_path) {
            Ok(_) => {
                event_file_exists = true;
            },
            Err(e) => match e.kind() {
                io::ErrorKind::NotFound => {},
                _ => return Err(std::convert::From::from(e))
            }
        };
    };

    // order matters here because POSIX FIFOs block in open calls

    let request_file = fs::File::open(request_path)?;
        
    // TODO send init request

    let response_file = fs::File::open(response_path)?;
    let events_file = fs::File::open(event_path)?;

    // TODO read init response
    
    let process = Process {
        pid: pid,
        request_file: request_file,
        response_file: response_file,
        events_file: events_file,
        architecture: Architecture::X32,
        protocol_version: 1,
        multithread_capable: false,
        running: false,
        terminating: false,
        terminated: false,
        user_data: std::ptr::null(),
        threads: vec![],
        root_dir: root_dir,
    };

    Ok(process)
}

/// Launch the UDI-controlled process
fn launch_process(executable: &str,
                  argv: &Vec<String>,
                  envp: &Vec<String>,
                  root_dir: &str) -> Result<u32, UdiError> {

    let mut command = std::process::Command::new(executable);

    let env = create_environment(envp, &root_dir);

    for entry in env {
        command.env(entry.0, entry.1);
    }

    for entry in argv {
        command.arg(entry);
    }

    let child = command.spawn()?;

    Ok(child.id())
}

/// Adds the UDI RT library into the LD_PRELOAD environ. var. It is
/// created at the end of the array if it does not already exist. Adds the UDI_ROOT_DIR_ENV
/// environment variable to the end of the array after LD_PRELOAD. This environment variable
/// is replaced if it already exists.
fn create_environment(envp: &Vec<String>, root_dir: &str) -> Vec<(String, String)> {
    let mut output;
    if envp.len() == 0 {
        output = vec![];
    }else{
        output = envp.iter().map(|s| {
            let mut field_iter = s.split("=");
            field_iter.next()
                      .map(|k| (k.to_owned(),
                                field_iter.fold(String::new(), |mut l,r| { l.push_str(r); l})))
                      .unwrap_or((s.clone(), String::new()))
        }).collect::<Vec<_>>();
    }

    // Update LD_PRELOAD to include the runtime library
    for item in &mut output {
        let k = &item.0;
        let v = &mut item.1;

        if k == "LD_PRELOAD" {
            v.push_str(":");
            v.push_str(DEFAULT_UDI_RT_LIB_NAME);
        }
    }

    output.push((UDI_ROOT_DIR_ENV.to_owned(), root_dir.to_owned()));

    output
}

/// Creates the root UDI filesystem for the user
fn create_root_udi_filesystem(root_dir: &String) -> Result<(), UdiError> {
    mkdir_ignore_exists(Path::new(root_dir))?;

    let user = users::get_current_username()
        .ok_or(UdiError::Library("Failed to retrieve username".to_owned()))?;

    let mut user_dir_path = PathBuf::from(root_dir);
    user_dir_path.push(user);

    mkdir_ignore_exists(user_dir_path.as_path())
}

/// Create the specified directory, ignoring the error if it already exists
fn mkdir_ignore_exists(dir: &Path) -> Result<(), UdiError> {
    match fs::create_dir(dir) {
        Ok(_) => Ok(()),
        Err(e) => match e.kind() {
            io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(std::convert::From::from(e))
        }
    }
}

impl Process {
    pub fn continue_process(&mut self) -> Result<(), UdiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
}
