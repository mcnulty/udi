//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate users;

use std::string::String;
use std::sync::Mutex;
use std::path::{PathBuf, Path};
use std::io::{self,Write};
use std::fs;

use super::error::UdiError;
use super::Process;
use super::to_arch;
use super::Thread;
use super::ThreadState;
use super::protocol;
use super::protocol::request;
use super::protocol::response;

const DEFAULT_UDI_ROOT_DIR: &'static str = "/tmp/udi";
const DEFAULT_UDI_RT_LIB_NAME: &'static str = "libudirt.so";
const UDI_ROOT_DIR_ENV: &'static str = "UDI_ROOT_DIR";
const REQUEST_FILE_NAME: &'static str = "request";
const RESPONSE_FILE_NAME: &'static str = "response";
const EVENTS_FILE_NAME: &'static str = "events";

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

    let mut root_dir_buf = PathBuf::from(&root_dir);
    root_dir_buf.push(pid.to_string());

    let process = initialize_process(pid, (*root_dir_buf.to_string_lossy()).to_owned())?;

    Ok(Mutex::new(process))
}

fn initialize_process(pid: u32, root_dir: String) -> Result<Process, UdiError> {

    let mut request_path_buf = PathBuf::from(&root_dir);
    request_path_buf.push(REQUEST_FILE_NAME);
    let request_path = request_path_buf.as_path();

    let mut response_path_buf = PathBuf::from(&root_dir);
    response_path_buf.push(RESPONSE_FILE_NAME);
    let response_path = response_path_buf.as_path();

    let mut event_path_buf = PathBuf::from(&root_dir);
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
                _ => return Err(::std::convert::From::from(e))
            }
        };
    };

    // order matters here because POSIX FIFOs block in open calls

    let mut request_file = fs::File::open(request_path)?;
        
    request_file.write_all(&protocol::serialize_message(&request::Init::new())?)?;

    let mut response_file = fs::File::open(response_path)?;
    let events_file = fs::File::open(event_path)?;

    let init: response::Init = protocol::read_response(response_file.by_ref())?;

    // Check compatibility with protocol version
    let version = determine_protocol(&init)?;
    
    let mut process = Process {
        pid: pid,
        request_file: request_file,
        response_file: response_file,
        events_file: events_file,
        architecture: to_arch(init.arch)?,
        protocol_version: version,
        multithread_capable: init.mt,
        running: false,
        terminating: false,
        terminated: false,
        user_data: ::std::ptr::null(),
        threads: vec![],
        root_dir: root_dir,
    };

    initialize_thread(&mut process, init.tid)?;

    Ok(process)
}

fn determine_protocol(init: &response::Init) -> Result<u32, UdiError> {
    if init.v != protocol::UDI_PROTOCOL_VERSION_1 {
        return Err(UdiError::Library(format!("Debuggee expects unsupported protocol version: {}",
                                  init.v)))
    }

    Ok(init.v)
}

/// Performs the init handshake for the new thread and adds it to the specified process
pub fn initialize_thread(process: &mut Process, tid: u64) -> Result<(), UdiError> {
    let mut request_path_buf = PathBuf::from(&process.root_dir);
    request_path_buf.push(format!("{:x}", tid));
    request_path_buf.push(REQUEST_FILE_NAME);
    let request_path = request_path_buf.as_path();

    let mut response_path_buf = PathBuf::from(&process.root_dir);
    response_path_buf.push(format!("{:x}", tid));
    response_path_buf.push(RESPONSE_FILE_NAME);
    let response_path = response_path_buf.as_path();

    let mut request_file = fs::File::open(request_path)?;

    request_file.write_all(&protocol::serialize_message(&request::Init::new())?)?;

    let mut response_file = fs::File::open(response_path)?;

    protocol::read_response::<response::Init, _>(response_file.by_ref())?;

    let thr = Thread {
        initial: process.threads.len() == 0,
        tid: tid,
        request_file: request_file,
        response_file: response_file,
        single_step: false,
        state: ThreadState::Running,
        user_data: ::std::ptr::null()
    };

    process.threads.push(thr);

    Ok(())
}

/// Launch the UDI-controlled process
fn launch_process(executable: &str,
                  argv: &Vec<String>,
                  envp: &Vec<String>,
                  root_dir: &str) -> Result<u32, UdiError> {

    let mut command = ::std::process::Command::new(executable);

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
            _ => Err(::std::convert::From::from(e))
        }
    }
}
