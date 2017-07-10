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

use super::Thread;
use super::error::UdiError;
use super::protocol::Register;
use super::UserData;

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

    pub fn get_pc(&mut self) -> Result<u64, UdiError> {
        Ok(0)
    }

    pub fn set_single_step(&mut self, setting: bool) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn get_next_instruction(&mut self) -> Result<u64, UdiError> {
        Ok(0)
    }

    pub fn get_state(&self) -> super::ThreadState {
        self.state
    }

    pub fn suspend(&mut self) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), UdiError> {
        Ok(())
    }

    pub fn read_register(&mut self, reg: Register) -> Result<u64, UdiError> {
        Ok(0)
    }

    pub fn write_register(&mut self, reg: Register, value: u64) -> Result<(), UdiError> {
        Ok(())
    }
}

impl PartialEq for Thread {
    fn eq(&self, other: &Thread) -> bool {
        self.tid == other.tid
    }
}
