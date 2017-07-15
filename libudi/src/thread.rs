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

use ::std::fs::File;
use ::std::io::Write;

use super::Thread;
use super::error::UdiError;
use super::protocol::Register;
use super::protocol::request;
use super::protocol::response;
use super::protocol::Architecture;
use super::protocol::serialize_message;
use super::protocol::read_response;
use super::UserData;

use serde::de::DeserializeOwned;
use serde::ser::Serialize;

impl Thread {

    pub fn set_user_data(&mut self, user_data: Box<UserData>) {
        self.user_data = Some(user_data);
    }

    pub fn get_user_data(&mut self) -> Option<&mut Box<UserData>> {
        self.user_data.as_mut()
    }

    pub fn get_tid(&self) -> u64 {
        self.tid
    }

    pub fn get_state(&self) -> super::ThreadState {
        self.state
    }

    pub fn get_pc(&mut self) -> Result<u64, UdiError> {
        let reg = match self.architecture {
            Architecture::X86 => Register::X86_EIP,
            Architecture::X86_64 => Register::X86_64_RIP
        };

        self.read_register(reg)
    }

    pub fn set_single_step(&mut self, setting: bool) -> Result<(), UdiError> {
        let msg = request::SingleStep::new(setting);

        self.send_request::<response::SingleStep, _>(&msg)?;

        Ok(())
    }

    pub fn get_next_instruction(&mut self) -> Result<u64, UdiError> {
        let msg = request::NextInstruction::new();

        let resp: response::NextInstruction = self.send_request(&msg)?;

        Ok(resp.addr)
    }

    pub fn suspend(&mut self) -> Result<(), UdiError> {
        let msg = request::ThreadSuspend::new();

        self.send_request::<response::ThreadSuspend, _>(&msg)?;

        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), UdiError> {
        let msg = request::ThreadResume::new();

        self.send_request::<request::ThreadResume, _>(&msg)?;

        Ok(())
    }

    pub fn read_register(&mut self, reg: Register) -> Result<u64, UdiError> {
        let msg = request::ReadRegister::new(reg as u32);

        let resp: response::ReadRegister = self.send_request(&msg)?;

        Ok(resp.value)
    }

    pub fn write_register(&mut self, reg: Register, value: u64) -> Result<(), UdiError> {
        let msg = request::WriteRegister::new(reg as u32, value);

        self.send_request::<response::WriteRegister, _>(&msg)?;

        Ok(())
    }

    fn send_request<T: DeserializeOwned, S: Serialize>(&mut self, msg: &S) -> Result<T, UdiError> {
        self.request_file.write_all(&serialize_message(msg)?)?;

        read_response::<T, File>(&mut self.response_file)
    }
}

impl PartialEq for Thread {
    fn eq(&self, other: &Thread) -> bool {
        self.tid == other.tid
    }
}
