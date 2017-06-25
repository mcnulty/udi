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

impl Thread {
    pub fn get_tid(&self) -> u64 {
        return self.tid;
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
}

impl PartialEq for Thread {
    fn eq(&self, other: &Thread) -> bool {
        self.tid == other.tid
    }
}
