/*
 * Copyright (c) 2011-2015, UDI Contributors
 * All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef _UDI_H
#define _UDI_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// UDI message metadata types
typedef uint32_t udi_request_type;
typedef uint32_t udi_response_type;
typedef uint32_t udi_event_type;

/**
 * architecture of debuggee
 */
typedef enum {
    UDI_ARCH_X86,
    UDI_ARCH_X86_64
} udi_arch_e;

/**
 * The version of the protocol
 */
typedef enum {
    UDI_PROTOCOL_VERSION_1 = 1
} udi_version_e;

/**
 * The running state for a thread
 */
typedef enum {
    UDI_TS_RUNNING = 0,
    UDI_TS_SUSPENDED,
} udi_thread_state_e;

/**
 * Registers
 */
typedef enum {
    // X86 registers
    UDI_X86_MIN = 0,
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

} udi_register_e;

/*
 * Request types
 */
typedef enum
{
    UDI_REQ_CONTINUE = 0,
    UDI_REQ_READ_MEM,
    UDI_REQ_WRITE_MEM,
    UDI_REQ_READ_REGISTER,
    UDI_REQ_WRITE_REGISTER,
    UDI_REQ_STATE,
    UDI_REQ_INIT,
    UDI_REQ_CREATE_BREAKPOINT,
    UDI_REQ_INSTALL_BREAKPOINT,
    UDI_REQ_REMOVE_BREAKPOINT,
    UDI_REQ_DELETE_BREAKPOINT,
    UDI_REQ_THREAD_SUSPEND,
    UDI_REQ_THREAD_RESUME,
    UDI_REQ_NEXT_INSTRUCTION,
    UDI_REQ_SINGLE_STEP,
    UDI_REQ_MAX,
    UDI_REQ_INVALID,
} udi_request_type_e;

/*
 * Response types
 */
typedef enum
{
    UDI_RESP_ERROR = 0,
    UDI_RESP_VALID,
    UDI_RESP_MAX
} udi_response_type_e;

/*
 * Event types
 */
typedef enum
{
    UDI_EVENT_ERROR = 0,
    UDI_EVENT_SIGNAL,
    UDI_EVENT_BREAKPOINT,
    UDI_EVENT_THREAD_CREATE,
    UDI_EVENT_THREAD_DEATH,
    UDI_EVENT_PROCESS_EXIT,
    UDI_EVENT_PROCESS_FORK,
    UDI_EVENT_PROCESS_EXEC,
    UDI_EVENT_SINGLE_STEP,
    UDI_EVENT_PROCESS_CLEANUP,
    UDI_EVENT_MAX,
    UDI_EVENT_UNKNOWN
} udi_event_type_e;

#ifdef __cplusplus
} // extern C
#endif

#endif
