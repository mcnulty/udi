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

use std::error::Error as StdError;
use std::io;
use std::sync;

use super::Process;
use super::Thread;

error_chain! {
    foreign_links {
        Io(io::Error);
        Cbor(serde_cbor::Error);
    }
    errors {
        Library(s: String) {
            description("library error")
            display("library error: {}", s)
        }
        Request(s: String) {
            description("invalid request")
            display("invalid request: {}", s)
        }
    }
}

impl<'a> From<sync::PoisonError<sync::MutexGuard<'a, Process>>> for Error {
    fn from(err: sync::PoisonError<sync::MutexGuard<'a, Process>>) -> Error {
        ErrorKind::Library(err.description().to_owned()).into()
    }
}

impl<'a> From<sync::PoisonError<sync::MutexGuard<'a, Thread>>> for Error {
    fn from(err: sync::PoisonError<sync::MutexGuard<'a, Thread>>) -> Error {
        ErrorKind::Library(err.description().to_owned()).into()
    }
}
