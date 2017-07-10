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
use ::std::slice::Iter;

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

    pub fn threads(&self) -> Iter<Arc<Mutex<Thread>>> {
        self.threads.iter()
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

    pub fn set_user_data(&mut self, user_data: super::UserData) {
        self.user_data = user_data;
    }

    pub fn get_user_data(&self) -> &super::UserData {
        &self.user_data
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

    pub fn refresh_state(&mut self) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn write_mem(&mut self, data: &[u8], addr: u64) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn read_mem(&mut self, size: u32, addr: u64) -> Result<Vec<u8>, UdiError> {
        Ok(Vec::new())
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.pid == other.pid
    }
}
