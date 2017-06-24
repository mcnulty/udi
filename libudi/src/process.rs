//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]
#![allow(unused_variables)]

use ::std::sync::{Mutex, Arc};

use super::error::UdiError;
use super::Process;
use super::Thread;

impl Process {

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

    pub fn get_architecture(&self) -> super::Architecture {
        self.architecture
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn continue_process(&mut self) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn create_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn install_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn delete_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        Ok(())
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.pid == other.pid
    }
}
