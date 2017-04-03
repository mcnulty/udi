//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate serde_cbor;

use std::error::Error;
use std::fmt;
use std::io;
use std::sync;

use super::Process;
use super::Thread;

#[derive(Debug)]
pub enum UdiError {
    Library(String),
    Request(String)
}

impl fmt::Display for UdiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UdiError::Library(ref s) => s.fmt(f),
            UdiError::Request(ref s) => s.fmt(f),
        }
    }
}

impl From<io::Error> for UdiError {
    fn from(err: io::Error) -> UdiError {
        UdiError::Library(err.description().to_owned())
    }
}

impl From<serde_cbor::Error> for UdiError {
    fn from(err: serde_cbor::Error) -> UdiError {
        UdiError::Library(err.description().to_owned())
    }
}

impl<'a> From<sync::PoisonError<sync::MutexGuard<'a, Process>>> for UdiError {
    fn from(err: sync::PoisonError<sync::MutexGuard<'a, Process>>) -> UdiError {
        UdiError::Library(err.description().to_owned())
    }
}

impl<'a> From<sync::PoisonError<sync::MutexGuard<'a, Thread>>> for UdiError {
    fn from(err: sync::PoisonError<sync::MutexGuard<'a, Thread>>) -> UdiError {
        UdiError::Library(err.description().to_owned())
    }
}

impl Error for UdiError {
    fn description(&self) -> &str {
        match *self {
            UdiError::Library(ref msg) => msg.as_str(),
            UdiError::Request(ref msg) => msg.as_str(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}
