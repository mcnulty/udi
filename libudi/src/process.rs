//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

use super::error::UdiError;
use super::Process;

impl Process {
    pub fn continue_process(&mut self) -> Result<(), UdiError> {
        Ok(())
    }
}
