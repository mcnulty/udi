//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

use std::sync::{Mutex,Arc};

use super::Process;
use super::Thread;
use super::error::UdiError;

#[derive(Debug)]
pub enum EventData {

}

#[derive(Debug)]
pub struct Event {
    pub process: Arc<Mutex<Process>>,
    pub thread: Arc<Mutex<Thread>>
}

pub fn wait_for_events(procs: Vec<Arc<Mutex<Process>>>) -> Result<Vec<Event>, UdiError> {
    drop(procs);

    Ok(vec![])
}

#[cfg(unix)]
mod sys {
}
