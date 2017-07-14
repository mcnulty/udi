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
use ::std::io::Write;
use ::std::fs::File;

use super::serde::de::DeserializeOwned;
use super::serde::Serialize;

use super::error::UdiError;
use super::Process;
use super::Thread;
use super::ThreadState;
use super::protocol::{request,response,read_response,serialize_message};
use super::UserData;

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

    pub fn set_user_data(&mut self, user_data: Box<UserData>) {
        self.user_data = Some(user_data);
    }

    pub fn get_user_data(&mut self) -> Option<&mut Box<UserData>> {
        self.user_data.as_mut()
    }

    pub fn continue_process(&mut self) -> Result<(), UdiError> {
        let msg = request::Continue::new(0);

        self.send_request::<response::Continue, _>(&msg)?;

        Ok(())
    }

    pub fn create_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        let msg = request::CreateBreakpoint::new(addr);

        self.send_request::<response::CreateBreakpoint, _>(&msg)?;

        Ok(())
    }

    pub fn install_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        let msg = request::InstallBreakpoint::new(addr);

        self.send_request::<response::InstallBreakpoint, _>(&msg)?;

        Ok(())
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        let msg = request::RemoveBreakpoint::new(addr);

        self.send_request::<response::RemoveBreakpoint, _>(&msg)?;

        Ok(())
    }

    pub fn delete_breakpoint(&mut self, addr: u64) -> Result<(), UdiError> {
        let msg = request::DeleteBreakpoint::new(addr);

        self.send_request::<response::DeleteBreakpoint, _>(&msg)?;

        Ok(())
    }

    pub fn refresh_state(&mut self) -> Result<(), UdiError> {
        let msg = request::State::new();

        let resp: response::States = self.send_request(&msg)?;

        for thr_ref in &self.threads {
            let mut thr = thr_ref.lock()?;

            for elem in &resp.states {
                if elem.tid == thr.tid {
                    thr.state = match elem.state {
                        0 => ThreadState::Running,
                        _ => ThreadState::Suspended
                    };
                }
            }
        }

        Ok(())
    }

    pub fn write_mem(&mut self, data: &[u8], addr: u64) -> Result<(), UdiError> {
        let msg = request::WriteMemory::new(addr, data);

        self.send_request::<response::WriteMemory, _>(&msg)?;

        Ok(())
    }

    pub fn read_mem(&mut self, size: u32, addr: u64) -> Result<Vec<u8>, UdiError> {
        let msg = request::ReadMemory::new(addr, size);

        let resp: response::ReadMemory = self.send_request(&msg)?;

        Ok(resp.data)
    }

    fn send_request<T: DeserializeOwned, S: Serialize>(&mut self, msg: &S) -> Result<T, UdiError> {
        self.request_file.write_all(&serialize_message(msg)?)?;

        read_response::<T, File>(&mut self.response_file)
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.pid == other.pid
    }
}
