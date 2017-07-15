// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate downcast_rs;

use std::fs;
use std::sync::{Mutex, Arc};

use downcast_rs::Downcast;

pub mod protocol;
pub mod error;
mod create;
mod process;
mod thread;
mod events;

pub use error::UdiError;
pub use create::create_process;
pub use create::ProcessConfig;
pub use events::Event;
pub use events::wait_for_events;
pub use protocol::event::EventData;
pub use protocol::Architecture;

pub trait UserData: Downcast + std::fmt::Debug {}
impl_downcast!(UserData);

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
    user_data: Option<Box<UserData>>,
    threads: Vec<Arc<Mutex<Thread>>>,
    root_dir: String
}

#[derive(Debug,Copy,Clone,PartialEq)]
pub enum ThreadState {
    Running,
    Suspended
}

#[derive(Debug)]
pub struct Thread {
    initial: bool,
    tid: u64,
    request_file: fs::File,
    response_file: fs::File,
    single_step: bool,
    state: ThreadState,
    architecture: Architecture,
    user_data: Option<Box<UserData>>
}
