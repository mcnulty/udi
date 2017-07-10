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
        pub fn new(sig: u32) -> Continue {
            Continue{ typ: Type::Continue, sig: sig }
        }
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct CreateBreakpoint {
        #[serde(rename = "type")]
        typ: Type,
        pub addr: u64
    }

    impl CreateBreakpoint {
        pub fn new(addr: u64) -> CreateBreakpoint {
            CreateBreakpoint{ typ: Type::CreateBreakpoint, addr: addr }
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
    pub struct Continue {}

    #[derive(Deserialize,Serialize,Debug)]
    pub struct CreateBreakpoint {}

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

enum_number!(Register {
    // X86 registers
    UDI_X86_MIN = 0,
    UDI_X86_GS = 1,
    UDI_X86_FS = 2,
    UDI_X86_ES = 3,
    UDI_X86_DS = 4,
    UDI_X86_EDI = 5,
    UDI_X86_ESI = 6,
    UDI_X86_EBP = 7,
    UDI_X86_ESP = 8,
    UDI_X86_EBX = 9,
    UDI_X86_EDX = 10,
    UDI_X86_ECX = 11,
    UDI_X86_EAX = 12,
    UDI_X86_CS = 13,
    UDI_X86_SS = 14,
    UDI_X86_EIP = 15,
    UDI_X86_FLAGS = 16,
    UDI_X86_ST0 = 17,
    UDI_X86_ST1 = 18,
    UDI_X86_ST2 = 19,
    UDI_X86_ST3 = 20,
    UDI_X86_ST4 = 21,
    UDI_X86_ST5 = 22,
    UDI_X86_ST6 = 23,
    UDI_X86_ST7 = 24,
    UDI_X86_MAX = 25,

    //UDI_X86_64 registers
    UDI_X86_64_MIN = 26,
    UDI_X86_64_R8 = 27,
    UDI_X86_64_R9 = 28,
    UDI_X86_64_R10 = 29,
    UDI_X86_64_R11 = 30,
    UDI_X86_64_R12 = 31,
    UDI_X86_64_R13 = 32,
    UDI_X86_64_R14 = 33,
    UDI_X86_64_R15 = 34,
    UDI_X86_64_RDI = 35,
    UDI_X86_64_RSI = 36,
    UDI_X86_64_RBP = 37,
    UDI_X86_64_RBX = 38,
    UDI_X86_64_RDX = 39,
    UDI_X86_64_RAX = 40,
    UDI_X86_64_RCX = 41,
    UDI_X86_64_RSP = 42,
    UDI_X86_64_RIP = 43,
    UDI_X86_64_CSGSFS = 44,
    UDI_X86_64_FLAGS = 45,
    UDI_X86_64_ST0 = 46,
    UDI_X86_64_ST1 = 47,
    UDI_X86_64_ST2 = 48,
    UDI_X86_64_ST3 = 49,
    UDI_X86_64_ST4 = 50,
    UDI_X86_64_ST5 = 51,
    UDI_X86_64_ST6 = 52,
    UDI_X86_64_ST7 = 53,
    UDI_X86_64_XMM0 = 54,
    UDI_X86_64_XMM1 = 55,
    UDI_X86_64_XMM2 = 56,
    UDI_X86_64_XMM3 = 57,
    UDI_X86_64_XMM4 = 58,
    UDI_X86_64_XMM5 = 59,
    UDI_X86_64_XMM6 = 60,
    UDI_X86_64_XMM7 = 61,
    UDI_X86_64_XMM8 = 62,
    UDI_X86_64_XMM9 = 63,
    UDI_X86_64_XMM10 = 64,
    UDI_X86_64_XMM11 = 65,
    UDI_X86_64_XMM12 = 66,
    UDI_X86_64_XMM13 = 67,
    UDI_X86_64_XMM14 = 68,
    UDI_X86_64_XMM15 = 69,
    UDI_X86_64_MAX = 70,
});
