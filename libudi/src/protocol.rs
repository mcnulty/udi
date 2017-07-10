//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]
#![allow(non_camel_case_types)]

extern crate serde_cbor;

use std::io::{Read,ErrorKind};

use serde::de::{Deserialize, DeserializeOwned};
use serde::ser::Serialize;
use self::serde_cbor::de::Deserializer;

use super::error::UdiError;

pub const UDI_PROTOCOL_VERSION_1: u32 = 1;

// From serde documentation
macro_rules! enum_number {
    ($name:ident { $($variant:ident = $value:expr, )* }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name {
            $($variant = $value,)*
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: ::serde::Serializer
            {
                // Serialize the enum as a u64.
                serializer.serialize_u64(*self as u64)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: ::serde::Deserializer<'de>
            {
                struct Visitor;

                impl<'de> ::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                        formatter.write_str("positive integer")
                    }

                    fn visit_u64<E>(self, value: u64) -> Result<$name, E>
                        where E: ::serde::de::Error
                    {
                        // Rust does not come with a simple way of converting a
                        // number to an enum, so use a big `match`.
                        match value {
                            $( $value => Ok($name::$variant), )*
                            _ => Err(E::custom(
                                format!("unknown {} value: {}",
                                stringify!($name), value))),
                        }
                    }
                }

                // Deserialize the enum from a u64.
                deserializer.deserialize_u64(Visitor)
            }
        }
    }
}

pub mod request {

	enum_number!(Type {
        Continue = 0,
        ReadMemory = 1,
        WriteMemory = 2,
        ReadRegister = 3,
        WriteRegister = 4,
        State = 5,
        Init = 6,
        CreateBreakpoint = 7,
        InstallBreakpoint = 8,
        RemoveBreakpoint = 9,
        DeleteBreakpoint = 10,
        ThreadSuspend = 11,
        ThreadResume = 12,
        NextInstruction = 13,
        SingleStep = 14,
	});

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Init {
        #[serde(rename = "type")]
        typ: Type,
    }

    impl Init {
        pub fn new() -> Init {
            Init{ typ: Type::Init }
        }
    }

    #[derive(Deserialize, Serialize, Debug)]
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

    enum_number!(Type {
        Valid = 0,
        Error = 1,
    });

    #[derive(Deserialize,Serialize,Debug)]
    pub struct Init {
        pub v: u32,
        pub arch: u32,
        pub mt: bool,
        pub tid: u64
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct ResponseError {
        pub code: u32,
        pub msg: String
    }
}

pub fn serialize_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, UdiError> {
    Ok(serde_cbor::to_vec(msg)?)
}

pub fn read_response<T: DeserializeOwned, R: Read>(reader: &mut R) -> Result<T, UdiError> {
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

    enum_number!(Type {
        Error = 0,
        Signal = 1,
        Breakpoint = 2,
        ThreadCreate = 3,
        ThreadDeath = 4,
        ProcessExit = 5,
        ProcessFork = 6,
        ProcessExec = 7,
        SingleStep = 8,
        ProcessCleanup = 9,
    });

    #[derive(Deserialize,Serialize,Debug)]
    pub struct EventError {
        pub msg: String
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct Signal {
        pub addr: u64,
        pub sig: u32
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct Breakpoint {
        pub addr: u64
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct ThreadCreate {
        pub tid: u64
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct ProcessExit {
        pub code: u32
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct ProcessFork {
        pub pid: u32
    }

    #[derive(Deserialize,Serialize,Debug)]
    pub struct ProcessExec {
        pub path: String,
        pub argv: Vec<String>,
        pub envp: Vec<String>
    }

    #[derive(Debug, PartialEq)]
    pub enum EventData {
        Error{ msg: String },
        Signal{ addr: u64, sig: u32 },
        Breakpoint{ addr: u64 },
        ThreadCreate{ tid: u64 },
        ThreadDeath,
        ProcessExit{ code: u32 },
        ProcessFork{ pid: u32 },
        ProcessExec{ path: String, argv: Vec<String>, envp: Vec<String> },
        SingleStep,
        ProcessCleanup
    }

    #[derive(Debug)]
    pub struct EventMessage {
        pub tid: u64,
        pub data: EventData
    }
}

#[derive(Debug)]
pub enum EventReadError {
    Eof,
    Udi(UdiError)
}

impl From<serde_cbor::Error> for EventReadError {
    fn from(err: serde_cbor::Error) -> EventReadError {
        match err {
            serde_cbor::Error::Io(ioe) => {
                match ioe.kind() {
                    ErrorKind::UnexpectedEof => EventReadError::Eof,
                    _ => EventReadError::Udi(::std::convert::From::from(ioe))
                }
            },
            _ => EventReadError::Udi(::std::convert::From::from(err))
        }
    }
}

pub fn read_event<R: Read>(reader: R) -> Result<event::EventMessage, EventReadError> {
    let mut de = Deserializer::new(reader);

    let event_type: event::Type = Deserialize::deserialize(&mut de)?;
    let tid: u64 = Deserialize::deserialize(&mut de)?;

    let data = deserialize_event_data(&mut de, &event_type)?;

    Ok(event::EventMessage{ tid: tid, data: data })
}

fn deserialize_event_data<R: Read>(de: &mut Deserializer<R>, event_type: &event::Type)
    -> Result<event::EventData, EventReadError> {

    let event_data = match *event_type {
        event::Type::Error => {
            let error_data: event::EventError = Deserialize::deserialize(de)?;
            event::EventData::Error{ msg: error_data.msg }
        },
        event::Type::Signal => {
            let signal_data: event::Signal = Deserialize::deserialize(de)?;
            event::EventData::Signal{ addr: signal_data.addr, sig: signal_data.sig }
        },
        event::Type::Breakpoint => {
            let brkpt_data: event::Breakpoint = Deserialize::deserialize(de)?;
            event::EventData::Breakpoint{ addr: brkpt_data.addr }
        },
        event::Type::ThreadCreate => {
            let thr_create_data: event::ThreadCreate = Deserialize::deserialize(de)?;
            event::EventData::ThreadCreate{ tid: thr_create_data.tid }
        },
        event::Type::ThreadDeath => {
            event::EventData::ThreadDeath
        },
        event::Type::ProcessExit => {
            let exit_data: event::ProcessExit = Deserialize::deserialize(de)?;
            event::EventData::ProcessExit{ code: exit_data.code }
        },
        event::Type::ProcessFork => {
            let fork_data: event::ProcessFork = Deserialize::deserialize(de)?;
            event::EventData::ProcessFork{ pid: fork_data.pid }
        },
        event::Type::ProcessExec => {
            let exec_data: event::ProcessExec = Deserialize::deserialize(de)?;
            event::EventData::ProcessExec{
                path: exec_data.path,
                argv: exec_data.argv,
                envp: exec_data.envp
            }
        },
        event::Type::SingleStep => {
            event::EventData::SingleStep
        },
        event::Type::ProcessCleanup => {
            event::EventData::ProcessCleanup
        }
    };

    Ok(event_data)
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
