//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

use ::std::sync::{Mutex, Arc};

use super::error::UdiError;
use super::Process;
use super::Thread;

impl Process {
    pub fn continue_process(&mut self) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn is_multithread_capable(&self) -> bool {
        self.multithread_capable
    }

    pub fn get_initial_thread(&self) -> Arc<Mutex<Thread>> {
        assert!(self.threads.len() > 0);

        self.threads[0].clone()
    }

    pub fn get_pid(&self) -> u32 {
        self.pid
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.pid == other.pid
    }
}
