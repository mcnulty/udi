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

use std::io::Read;
use serde::Deserialize;
use serde::ser::Serialize;
use self::serde_cbor::de::Deserializer;

use super::error::UdiError;

pub const UDI_PROTOCOL_VERSION_1: u32 = 1;

pub mod request {

    #[derive(Deserialize, Serialize, Debug)]
    pub enum Type {
        Continue,
        ReadMemory,
        WriteMemory,
        ReadRegister,
        WriteRegister,
        State,
        Init,
        CreateBreakpoint,
        InstallBreakpoint,
        RemoveBreakpoint,
        DeleteBreakpoint,
        ThreadSuspend,
        ThreadResume,
        NextInstruction,
        SingleStep,
    }

    #[derive(Serialize,Debug)]
    pub struct Init {
        #[serde(rename = "type")]
        typ: Type,
    }

    impl Init {
        pub fn new() -> Init {
            Init{ typ: Type::Init }
        }
    }

    #[derive(Serialize,Debug)]
    pub struct Continue {
        #[serde(rename = "type")]
        typ: Type,
        pub sig: u32
    }

    impl Continue {
        pub fn new() -> Continue {
            Continue{ typ: Type::Continue, sig: 0 }
        }
    }
}

pub mod response {

    #[derive(Deserialize,Debug)]
    pub enum Type {
        Valid,
        Error
    }

    #[derive(Deserialize,Debug)]
    pub struct Init {
        pub v: u32,
        pub arch: u32,
        pub mt: bool,
        pub tid: u64
    }

    #[derive(Deserialize,Debug)]
    pub struct ResponseError {
        pub code: u32,
        pub msg: String
    }
}

pub fn serialize_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, UdiError> {
    Ok(serde_cbor::to_vec(msg)?)
}

pub fn read_response<T: Deserialize, R: Read>(reader: R) -> Result<T, UdiError> {
    let mut de = Deserializer::new(reader);
    
    let response_type: response::Type = Deserialize::deserialize(&mut de)?;
    <request::Type as Deserialize>::deserialize(&mut de)?;

    match response_type {
        response::Type::Valid => Ok(Deserialize::deserialize(&mut de)?),
        response::Type::Error => {
            let err: response::ResponseError = Deserialize::deserialize(&mut de)?;
            Err(UdiError::Request(err.msg))
        }
    }
}

pub mod event {

    #[derive(Deserialize, Debug)]
    pub enum Type {
        Error,
        Signal,
        Breakpoint,
        ThreadCreate,
        ThreadDeath,
        ProcessExit,
        ProcessFork,
        ProcessExec,
        SingleStep,
        ProcessCleanup
    }
}

#[repr(C)]
pub enum Register {
    // X86 registers
    UDI_X86_MIN,
    UDI_X86_GS,
    UDI_X86_FS,
    UDI_X86_ES,
    UDI_X86_DS,
    UDI_X86_EDI,
    UDI_X86_ESI,
    UDI_X86_EBP,
    UDI_X86_ESP,
    UDI_X86_EBX,
    UDI_X86_EDX,
    UDI_X86_ECX,
    UDI_X86_EAX,
    UDI_X86_CS,
    UDI_X86_SS,
    UDI_X86_EIP,
    UDI_X86_FLAGS,
    UDI_X86_ST0,
    UDI_X86_ST1,
    UDI_X86_ST2,
    UDI_X86_ST3,
    UDI_X86_ST4,
    UDI_X86_ST5,
    UDI_X86_ST6,
    UDI_X86_ST7,
    UDI_X86_MAX,

    //UDI_X86_64 registers
    UDI_X86_64_MIN,
    UDI_X86_64_R8,
    UDI_X86_64_R9,
    UDI_X86_64_R10,
    UDI_X86_64_R11,
    UDI_X86_64_R12,
    UDI_X86_64_R13,
    UDI_X86_64_R14,
    UDI_X86_64_R15,
    UDI_X86_64_RDI,
    UDI_X86_64_RSI,
    UDI_X86_64_RBP,
    UDI_X86_64_RBX,
    UDI_X86_64_RDX,
    UDI_X86_64_RAX,
    UDI_X86_64_RCX,
    UDI_X86_64_RSP,
    UDI_X86_64_RIP,
    UDI_X86_64_CSGSFS,
    UDI_X86_64_FLAGS,
    UDI_X86_64_ST0,
    UDI_X86_64_ST1,
    UDI_X86_64_ST2,
    UDI_X86_64_ST3,
    UDI_X86_64_ST4,
    UDI_X86_64_ST5,
    UDI_X86_64_ST6,
    UDI_X86_64_ST7,
    UDI_X86_64_XMM0,
    UDI_X86_64_XMM1,
    UDI_X86_64_XMM2,
    UDI_X86_64_XMM3,
    UDI_X86_64_XMM4,
    UDI_X86_64_XMM5,
    UDI_X86_64_XMM6,
    UDI_X86_64_XMM7,
    UDI_X86_64_XMM8,
    UDI_X86_64_XMM9,
    UDI_X86_64_XMM10,
    UDI_X86_64_XMM11,
    UDI_X86_64_XMM12,
    UDI_X86_64_XMM13,
    UDI_X86_64_XMM14,
    UDI_X86_64_XMM15,
    UDI_X86_64_MAX
}
