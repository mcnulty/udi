//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

extern crate mio;

use std::sync::{Mutex,MutexGuard,Arc};
use std::io::{self, Read};
use std::collections::HashMap;

use self::mio::{Poll, Events, Ready, PollOpt, Token};

use super::Process;
use super::Thread;
use super::error::UdiError;
use super::protocol::event::EventData;
use super::protocol::event::EventMessage;
use super::protocol::read_event;
use super::protocol::EventReadError;

#[derive(Debug)]
pub struct Event {
    pub process: Arc<Mutex<Process>>,
    pub thread: Arc<Mutex<Thread>>,
    pub data: EventData
}

struct BufWrapper {
    pub buf: Vec<u8>,
    pub pos: usize
}

impl Read for BufWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut slice = &self.buf as &[u8];

        slice = slice.split_at(self.pos).1;

        let bytes_read = slice.read(buf)?;
        self.pos += bytes_read;
        Ok(bytes_read)
    }
}

struct ProcessContext<'a> {
    proc_ref: Arc<Mutex<Process>>,
    process: MutexGuard<'a, Process>,
    event_buf: BufWrapper
}

pub fn wait_for_events(procs: Vec<Arc<Mutex<Process>>>) -> Result<Vec<Event>, UdiError> {

    let poll = Poll::new()?;
    let mut event_procs = HashMap::new();
    for process in &procs {
        let mut ctx = ProcessContext{
            proc_ref: process.clone(),
            process: process.lock()?,
            event_buf: BufWrapper{ buf: vec![], pos: 0}
        };

        let event_source = sys::EventSource::new(ctx.process.events_file.by_ref());
        let token = Token(ctx.process.pid as usize);

        poll.register(&event_source, token, Ready::readable(), PollOpt::edge())?;

        event_procs.insert(token, ctx);
    }

    let mut event_pending = false;
    let mut output: Vec<Event> = vec![];
    while output.len() == 0 || event_pending {
        event_pending = false;

        let mut events = Events::with_capacity(procs.len());

        poll.poll(&mut events, None)?;

        for event in &events {
            if event.readiness().is_readable() {
                let event_token = event.token();
                if let Some(ctx) = event_procs.get_mut(&event_token) {
                    let proc_event_pending = handle_read_event(&mut *ctx, &mut output)?;

                    if proc_event_pending {
                        event_pending = proc_event_pending;
                    }
                }else{
                    let msg = format!("Unknown event token {:?}", event_token);
                    return Err(UdiError::Library(msg));
                }
            }
        }
    }

    Ok(output)
}

fn handle_read_event(ctx: &mut ProcessContext, output: &mut Vec<Event>)
    -> Result<bool, UdiError> {

    let proc_event_pending = match ctx.process
                                      .events_file
                                      .read_to_end(&mut ctx.event_buf.buf) {
        Ok(_) => {
            // Process has closed its pipe
            if read_events_for_process(ctx, output)? {
                return Err(UdiError::Library(
                    "Received incomplete event before debuggee closed pipe".to_owned()));
            }

            // Add the cleanup event
            output.push(Event{
                process: ctx.proc_ref.clone(),
                thread: ctx.process.threads[0].clone(),
                data: EventData::ProcessCleanup
            });

            ctx.process.terminated = true;
            
            false
        },
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock => {
                read_events_for_process(ctx, output)?
            },
            _ => return Err(::std::convert::From::from(e))
        }
    };

    Ok(proc_event_pending)
}

fn read_events_for_process(ctx: &mut ProcessContext, output: &mut Vec<Event>)
    -> Result<bool, UdiError> {

    let mut messages = vec![];

    let pending = read_events_from_buf(&mut ctx.event_buf, &mut messages)?;

    if pending {
        Ok(true)
    }else{
        for message in messages {
            // Locate the event thread
            let mut t = None;
            for thr in &(ctx.process.threads) {
                if thr.lock()?.tid == message.tid {
                    t = Some(thr.clone());
                    break;
                }
            }

            ctx.process.running = false;

            match message.data {
                EventData::ProcessExit{ .. } => {
                    ctx.process.terminating = true;
                }
                _ => {}
            }

            match t {
                Some(thr) => {
                    output.push(Event{
                        process: ctx.proc_ref.clone(),
                        thread: thr,
                        data: message.data
                    });
                },
                None => {
                    let msg = format!("Failed to locate event thread with tid {:?}", message.tid);
                    return Err(UdiError::Library(msg));
                }
            }
        }

        Ok(false)
    }
}

fn read_events_from_buf(event_buf: &mut BufWrapper,
                        output: &mut Vec<EventMessage>) -> Result<bool, UdiError> {

    while event_buf.buf.len() > 0 {
        let prev_pos = event_buf.pos;

        match read_event(&mut *event_buf) {
            Ok(message) => {
                // Remove the read data from the buffer
                event_buf.buf.drain(0..event_buf.pos);
                event_buf.pos = 0;

                output.push(message);
            },
            Err(EventReadError::Eof) => {
                // Roll back the position of the buffer
                event_buf.pos = prev_pos;

                return Ok(true);
            },
            Err(EventReadError::Udi(e)) => {
                return Err(e);
            }
        }
    }

    Ok(false)
}

#[cfg(unix)]
mod sys {

    use std::os::unix::io::RawFd;
    use std::os::unix::io::AsRawFd;
    use std::io;
    use std::fs;

    use super::mio::{Ready, Poll, PollOpt, Token};
    use super::mio::unix::EventedFd;
    use super::mio::event::Evented;

    pub struct EventSource {
        fd: RawFd
    }

    impl EventSource {
        pub fn new(file: &fs::File) -> EventSource {
            EventSource{ fd: file.as_raw_fd() }
        }
    }

    impl Evented for EventSource {
        fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
            -> io::Result<()> {

            EventedFd(&self.fd).register(poll, token, interest, opts)
        }

        fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
            -> io::Result<()> {
                
            EventedFd(&self.fd).reregister(poll, token, interest, opts)
        }

        fn deregister(&self, poll: &Poll) -> io::Result<()> {
            EventedFd(&self.fd).deregister(poll)
        }
    }
}

#[cfg(test)]
mod tests {

    extern crate serde_cbor;

    use super::read_events_from_buf;
    use super::super::protocol;
    use self::serde_cbor::ser::to_writer;
    use super::BufWrapper;
    use super::EventMessage;

    #[test]
    fn test_read_events_from_buf() {
        let mut buf: Vec<u8> = vec![];

        to_writer(&mut buf, &protocol::event::Type::Breakpoint).unwrap();

        let tid: u64 = 1;
        to_writer(&mut buf, &tid).unwrap();

        let len_before_data = buf.len();

        to_writer(&mut buf, &protocol::event::Breakpoint{ addr: 0xdeadbeef }).unwrap();

        let full_buf = buf.clone();

        let incomplete_buf = buf.drain(0..len_before_data).collect();

        let mut incomplete_buf_wrapper = BufWrapper{ buf: incomplete_buf, pos: 0 };

        let mut messages: Vec<EventMessage> = vec![];

        assert_eq!(true, read_events_from_buf(&mut incomplete_buf_wrapper, &mut messages).unwrap());
        assert_eq!(0, messages.len());

        let mut full_buf_wrapper = BufWrapper{ buf: full_buf, pos: 0 };

        assert_eq!(false, read_events_from_buf(&mut full_buf_wrapper, &mut messages).unwrap());
        assert_eq!(1, messages.len());

        let message = &messages[0];
        assert_eq!(1, message.tid);

        match message.data {
            protocol::event::EventData::Breakpoint{ addr } => {
                assert_eq!(0xdeadbeef, addr);
            },
            _ => {
                panic!();
            }
        }
    }
}
