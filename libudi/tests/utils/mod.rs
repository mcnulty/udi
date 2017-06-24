//
// Copyright (c) 2011-2017, UDI Contributors
// All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
#![deny(warnings)]

use ::std::sync::{Mutex, Arc};

use udi::Process;
use udi::Thread;
use udi::EventData;
use udi::wait_for_events;

pub fn wait_for_exit(process: &Arc<Mutex<Process>>,
                     thread: &Arc<Mutex<Thread>>,
                     expected_status: u32) {

    wait_for_event(process, thread, &EventData::ProcessExit{ code: expected_status });

    process.lock().expect("Failed unlock process").continue_process().expect("Continue failed");

    wait_for_event(process, thread, &EventData::ProcessCleanup);
}

pub fn wait_for_event(process: &Arc<Mutex<Process>>,
                      thread: &Arc<Mutex<Thread>>,
                      expected_event: &EventData) {

    let procs = vec![ process.clone() ];

    let events = wait_for_events(procs).expect("Failed to wait for events");
    assert_eq!(1, events.len());

    let event = &events[0];
    assert_eq!(*expected_event, event.data);
    assert_proc_eq(&process, &event.process);
    assert_thr_eq(&thread, &event.thread);
}

pub fn assert_proc_eq(lhs: &Arc<Mutex<Process>>, rhs: &Arc<Mutex<Process>>) {
    let lhs_pid = lhs.lock().expect("Failed to unlock lhs process").get_pid();
    let rhs_pid = rhs.lock().expect("Failed to unlock rhs process").get_pid();
    assert_eq!(lhs_pid, rhs_pid);
}

pub fn assert_thr_eq(lhs: &Arc<Mutex<Thread>>, rhs: &Arc<Mutex<Thread>>) {
    let lhs_tid = lhs.lock().expect("Failed to unlock lhs thread").get_tid();
    let rhs_tid = rhs.lock().expect("Failed to unlock rhs thread").get_tid();
    assert_eq!(lhs_tid, rhs_tid);
}
