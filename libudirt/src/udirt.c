/*
 * Copyright (c) 2011-2018, UDI Contributors
 * All rights reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// UDI debuggee implementation common between all platforms

#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "udirt.h"

// constants
enum { BREAKPOINT_HASH_SIZE = 256 };

const uint64_t UDI_SINGLE_THREAD_ID = 0xC0FFEEABC;

const char * const UDI_ROOT_DIR_ENV = "UDI_ROOT_DIR";
const char * const REQUEST_FILE_NAME = "request";
const char * const RESPONSE_FILE_NAME = "response";
const char * const EVENTS_FILE_NAME = "events";
const char * const UDI_DEBUG_ENV = "UDI_DEBUG";

const int RESULT_SUCCESS = 0;
const int RESULT_ERROR = -1;
const int RESULT_FAILURE = -2;

 // not enabled until initialization complete
char *UDI_ROOT_DIR;
int udi_debug_on = 0;
int udi_enabled = 0;

// read / write handling
static void *mem_access_addr = NULL;
static size_t mem_access_size = 0;

static int aborting_mem_access = 0;
static int performing_mem_access = 0;

static void *mem_abort_label = NULL;

void *get_mem_access_addr() {
    return mem_access_addr;
}

size_t get_mem_access_size() {
    return mem_access_size;
}

unsigned long abort_mem_access() {
    aborting_mem_access = 1;

    return (unsigned long)mem_abort_label;
}

int is_performing_mem_access() {
    return performing_mem_access;
}

/**
 * Copy memory byte to byte to allow a signal handler to abort
 * the copy
 *
 * @param dest the destination memory address
 * @param src the source memory address
 * @param n the number of bytes to copy
 *
 * @return 0 on success; non-zero otherwise
 *
 * @see memcpy
 */
static
int abortable_memcpy(void *dest, const void *src, size_t n) {
    // This should stop the compiler from messing with the label
    static void *abort_label_addr = &&abort_label;

    mem_abort_label = abort_label_addr;

    // Hopefully when compiled with optimization, this code will be vectorized if possible
    unsigned char *uc_dest = (unsigned char *)dest;
    const unsigned char *uc_src = (const unsigned char *)src;

    size_t i = 0;
    for (i = 0; i < n; ++i) {
        uc_dest[i] = uc_src[i];
    }

abort_label:
    if ( aborting_mem_access ) {
        aborting_mem_access = 0;
        return -1;
    }

    return 0;
}

/**
 * Copy memory with hooks before and after the copy to allow
 * for example changing permissions on pages in memory.
 *
 * @param dest the destination memory address
 * @param src the source memory address
 * @param num_bytes the number of bytes
 * @param errmsg the error message populated by this method
 *
 * @return 0 on success; non-zero otherwise
 */
static
int udi_memcpy(void *dest, const void *src, size_t num_bytes, udi_errmsg *errmsg) {
    int mem_result = 0;

    void *pre_access_result = pre_mem_access_hook();

    if ( pre_access_result == NULL ) {
        return -1;
    }

    performing_mem_access = 1;
    mem_result = abortable_memcpy(dest, src, num_bytes);
    performing_mem_access = 0;

    if ( post_mem_access_hook(pre_access_result) ) {
        return -1;
    }

    return mem_result;
}

/**
 * Reads memory from the specified source into the specified
 * destination
 *
 * @param dest the destination memory address
 * @param src the source memory address
 * @param num_bytes the number of bytes to read
 * @param errmsg the error message possibly populated by this function
 *
 * @return 0, success; non-zero otherwise
 */
int read_memory(void *dest, const void *src, size_t num_bytes, udi_errmsg *errmsg) {
    mem_access_addr = (void *)src;
    mem_access_size = num_bytes;

    return udi_memcpy(dest, src, num_bytes, errmsg);
}

/**
 * Writes into the specified memory address using the specified
 * source.
 *
 * @param dest the destination of the write
 * @param src the source of the write
 * @param num_bytes the number of bytes to write
 * @param errmsg the error message set by this function
 */
int write_memory(void *dest, const void *src, size_t num_bytes, udi_errmsg *errmsg) {
    mem_access_addr = dest;
    mem_access_size = num_bytes;

    return udi_memcpy(dest, src, num_bytes, errmsg);
}

// breakpoint implementation

static breakpoint *breakpoints[BREAKPOINT_HASH_SIZE];

static inline
unsigned int breakpoint_hash(uint64_t address) {
    return (unsigned int)(address % BREAKPOINT_HASH_SIZE);
}

/**
 * Creates a breakpoint at the specified address
 *
 * @param breakpoint_addr the breakpoint address
 *
 * @return the created breakpoint, NULL on failure
 */
breakpoint *create_breakpoint(uint64_t breakpoint_addr) {
    breakpoint *new_breakpoint = (breakpoint *)udi_malloc(sizeof(breakpoint));

    if ( new_breakpoint == NULL ) {
        udi_printf("failed to allocate memory for breakpoint: %s\n",
                strerror(errno));
        return NULL;
    }

    memset(new_breakpoint, 0, sizeof(breakpoint));
    memset(new_breakpoint->saved_bytes, 0, sizeof(new_breakpoint->saved_bytes));
    new_breakpoint->address = breakpoint_addr;
    new_breakpoint->in_memory = 0;
    new_breakpoint->thread = NULL;

    unsigned int hash = breakpoint_hash(breakpoint_addr);

    // Add the breakpoint to the hash
    breakpoint *current_bp = breakpoints[hash];
    if (current_bp == NULL) {
        breakpoints[hash] = new_breakpoint;
        new_breakpoint->next_breakpoint = NULL;
    }else{
        breakpoint *tmp_breakpoint = current_bp;
        while(1) {
            if ( tmp_breakpoint->address == new_breakpoint->address ) {
                // Use the existing breakpoint
                udi_free(new_breakpoint);
                new_breakpoint = tmp_breakpoint;
                break;
            }

            if ( tmp_breakpoint->next_breakpoint == NULL ) {
                tmp_breakpoint->next_breakpoint = new_breakpoint;
                break;
            }
            tmp_breakpoint = tmp_breakpoint->next_breakpoint;
        }
    }

    return new_breakpoint;
}

/**
 * Installs the breakpoint into memory
 *
 * @param bp the breakpoint to install
 * @param errmsg the errmsg populated by the memory access
 *
 * @return 0 on success; non-zero otherwise
 */
int install_breakpoint(breakpoint *bp, udi_errmsg *errmsg) {
    if ( bp->in_memory ) return 0;

    int result = write_breakpoint_instruction(bp, errmsg);

    if ( result == 0 ) {
        bp->in_memory = 1;
    }

    return result;
}

/**
 * Removes the breakpoint from memory
 *
 * @param bp the breakpoint to remove
 * @param errmsg the errmsg populated by the memory access
 *
 * @return 0 on success; non-zero otherwise
 */
int remove_breakpoint(breakpoint *bp, udi_errmsg *errmsg) {
    if ( !bp->in_memory ) return 0;

    int result = write_saved_bytes(bp, errmsg);

    if ( result == 0 ) {
        bp->in_memory = 0;
    }

    return result;
}

/**
 * Removes the breakpoint from memory in preparation for a continue
 *
 * @param bp the breakpoint to remove
 * @param errmsg the errmsg populated by the memory access
 *
 * @return 0 on success; non-zero otherwise
 */
int remove_breakpoint_for_continue(breakpoint *bp, udi_errmsg *errmsg) {

    if ( !bp->in_memory ) return 0;

    // Don't set the in memory flag
    return write_saved_bytes(bp, errmsg);
}

/**
 * Deletes the breakpoint
 *
 * @param bp the breakpoint to delete
 * @param errmsg the errmsg populated by the memory access
 *
 * @return 0 on success; non-zero otherwise
 */
int delete_breakpoint(breakpoint *bp, udi_errmsg *errmsg) {
    int remove_result = remove_breakpoint(bp, errmsg);

    if ( remove_result ) return remove_result;

    unsigned int hash = breakpoint_hash(bp->address);

    breakpoint *tmp_breakpoint = breakpoints[hash];
    breakpoint *prev_breakpoint = breakpoints[hash];

    while ( tmp_breakpoint != NULL ) {
        if ( tmp_breakpoint->address == bp->address ) break;
        prev_breakpoint = tmp_breakpoint;
        tmp_breakpoint = prev_breakpoint->next_breakpoint;
    }

    if ( tmp_breakpoint == NULL || prev_breakpoint == NULL ) {
        snprintf(errmsg->msg, errmsg->size, "failed to delete breakpoint at %"PRIx64,
                bp->address);
        udi_printf("%s\n", errmsg->msg);
        return -1;
    }

    // single element in hash table bucket
    if ( prev_breakpoint == tmp_breakpoint ) {
        breakpoints[hash] = NULL;
    }else{
        prev_breakpoint->next_breakpoint = tmp_breakpoint->next_breakpoint;
    }

    udi_free(tmp_breakpoint);

    return 0;
}

/**
 * Finds an existing breakpoint, given its address
 *
 * @param breakpoint_addr
 *
 * @return the found breakpoint (NULL if not found)
 */
breakpoint *find_breakpoint(uint64_t breakpoint_addr) {
    breakpoint *tmp_breakpoint = breakpoints[breakpoint_hash(breakpoint_addr)];

    while ( tmp_breakpoint != NULL ) {
        if ( tmp_breakpoint->address == breakpoint_addr ) break;
        tmp_breakpoint = tmp_breakpoint->next_breakpoint;
    }

    return tmp_breakpoint;
}

/**
 * @return the protocol version for this execution
 */
udi_version_e get_protocol_version() {
    return UDI_PROTOCOL_VERSION_1;
}

#define CASE_TO_STR(x) case x: return #x

const char *request_type_str(udi_request_type_e req_type) {
    switch(req_type) {
        CASE_TO_STR(UDI_REQ_INVALID);
        CASE_TO_STR(UDI_REQ_CONTINUE);
        CASE_TO_STR(UDI_REQ_READ_MEM);
        CASE_TO_STR(UDI_REQ_WRITE_MEM);
        CASE_TO_STR(UDI_REQ_STATE);
        CASE_TO_STR(UDI_REQ_INIT);
        CASE_TO_STR(UDI_REQ_CREATE_BREAKPOINT);
        CASE_TO_STR(UDI_REQ_INSTALL_BREAKPOINT);
        CASE_TO_STR(UDI_REQ_REMOVE_BREAKPOINT);
        CASE_TO_STR(UDI_REQ_DELETE_BREAKPOINT);
        CASE_TO_STR(UDI_REQ_THREAD_SUSPEND);
        CASE_TO_STR(UDI_REQ_THREAD_RESUME);
        CASE_TO_STR(UDI_REQ_READ_REGISTER);
        CASE_TO_STR(UDI_REQ_WRITE_REGISTER);
        CASE_TO_STR(UDI_REQ_NEXT_INSTRUCTION);
        CASE_TO_STR(UDI_REQ_SINGLE_STEP);
        default: return "UNKNOWN";
    }
}

const char *event_type_str(udi_event_type_e event_type) {
    switch(event_type) {
        CASE_TO_STR(UDI_EVENT_UNKNOWN);
        CASE_TO_STR(UDI_EVENT_ERROR);
        CASE_TO_STR(UDI_EVENT_SIGNAL);
        CASE_TO_STR(UDI_EVENT_BREAKPOINT);
        CASE_TO_STR(UDI_EVENT_THREAD_CREATE);
        CASE_TO_STR(UDI_EVENT_THREAD_DEATH);
        CASE_TO_STR(UDI_EVENT_PROCESS_EXIT);
        CASE_TO_STR(UDI_EVENT_PROCESS_FORK);
        CASE_TO_STR(UDI_EVENT_PROCESS_EXEC);
        CASE_TO_STR(UDI_EVENT_SINGLE_STEP);
        default: return "UNSPECIFIED";
    }
}

const char *arch_str(udi_arch_e arch) {
    switch (arch) {
        CASE_TO_STR(UDI_ARCH_X86);
        CASE_TO_STR(UDI_ARCH_X86_64);
        default: return "UNSPECIFIED";
    }
}

const char *register_str(udi_register_e reg) {
    switch (reg) {
        CASE_TO_STR(UDI_X86_MIN);
        CASE_TO_STR(UDI_X86_GS);
        CASE_TO_STR(UDI_X86_FS);
        CASE_TO_STR(UDI_X86_ES);
        CASE_TO_STR(UDI_X86_DS);
        CASE_TO_STR(UDI_X86_EDI);
        CASE_TO_STR(UDI_X86_ESI);
        CASE_TO_STR(UDI_X86_EBP);
        CASE_TO_STR(UDI_X86_ESP);
        CASE_TO_STR(UDI_X86_EBX);
        CASE_TO_STR(UDI_X86_EDX);
        CASE_TO_STR(UDI_X86_ECX);
        CASE_TO_STR(UDI_X86_EAX);
        CASE_TO_STR(UDI_X86_CS);
        CASE_TO_STR(UDI_X86_SS);
        CASE_TO_STR(UDI_X86_EIP);
        CASE_TO_STR(UDI_X86_FLAGS);
        CASE_TO_STR(UDI_X86_ST0);
        CASE_TO_STR(UDI_X86_ST1);
        CASE_TO_STR(UDI_X86_ST2);
        CASE_TO_STR(UDI_X86_ST3);
        CASE_TO_STR(UDI_X86_ST4);
        CASE_TO_STR(UDI_X86_ST5);
        CASE_TO_STR(UDI_X86_ST6);
        CASE_TO_STR(UDI_X86_ST7);
        CASE_TO_STR(UDI_X86_MAX);
        CASE_TO_STR(UDI_X86_64_MIN);
        CASE_TO_STR(UDI_X86_64_R8);
        CASE_TO_STR(UDI_X86_64_R9);
        CASE_TO_STR(UDI_X86_64_R10);
        CASE_TO_STR(UDI_X86_64_R11);
        CASE_TO_STR(UDI_X86_64_R12);
        CASE_TO_STR(UDI_X86_64_R13);
        CASE_TO_STR(UDI_X86_64_R14);
        CASE_TO_STR(UDI_X86_64_R15);
        CASE_TO_STR(UDI_X86_64_RDI);
        CASE_TO_STR(UDI_X86_64_RSI);
        CASE_TO_STR(UDI_X86_64_RBP);
        CASE_TO_STR(UDI_X86_64_RBX);
        CASE_TO_STR(UDI_X86_64_RDX);
        CASE_TO_STR(UDI_X86_64_RAX);
        CASE_TO_STR(UDI_X86_64_RCX);
        CASE_TO_STR(UDI_X86_64_RSP);
        CASE_TO_STR(UDI_X86_64_RIP);
        CASE_TO_STR(UDI_X86_64_CSGSFS);
        CASE_TO_STR(UDI_X86_64_FLAGS);
        CASE_TO_STR(UDI_X86_64_ST0);
        CASE_TO_STR(UDI_X86_64_ST1);
        CASE_TO_STR(UDI_X86_64_ST2);
        CASE_TO_STR(UDI_X86_64_ST3);
        CASE_TO_STR(UDI_X86_64_ST4);
        CASE_TO_STR(UDI_X86_64_ST5);
        CASE_TO_STR(UDI_X86_64_ST6);
        CASE_TO_STR(UDI_X86_64_ST7);
        CASE_TO_STR(UDI_X86_64_XMM0);
        CASE_TO_STR(UDI_X86_64_XMM1);
        CASE_TO_STR(UDI_X86_64_XMM2);
        CASE_TO_STR(UDI_X86_64_XMM3);
        CASE_TO_STR(UDI_X86_64_XMM4);
        CASE_TO_STR(UDI_X86_64_XMM5);
        CASE_TO_STR(UDI_X86_64_XMM6);
        CASE_TO_STR(UDI_X86_64_XMM7);
        CASE_TO_STR(UDI_X86_64_XMM8);
        CASE_TO_STR(UDI_X86_64_XMM9);
        CASE_TO_STR(UDI_X86_64_XMM10);
        CASE_TO_STR(UDI_X86_64_XMM11);
        CASE_TO_STR(UDI_X86_64_XMM12);
        CASE_TO_STR(UDI_X86_64_XMM13);
        CASE_TO_STR(UDI_X86_64_XMM14);
        CASE_TO_STR(UDI_X86_64_XMM15);
        CASE_TO_STR(UDI_X86_64_MAX);
        default: return "UNSPECIFIED";
    }
}

int validate_register(udi_register_e reg, udi_errmsg *errmsg) {

    int result = 0;
    udi_arch_e arch = get_architecture();
    switch (arch) {
        case UDI_ARCH_X86:
            if (reg <= UDI_X86_MIN || reg >= UDI_X86_MAX) {
                result = -1;
            }
            break;
        case UDI_ARCH_X86_64:
            if (reg <= UDI_X86_64_MIN || reg >= UDI_X86_64_MAX) {
                result = -1;
            }
            break;
    }

    if (result != 0) {
        snprintf(errmsg->msg, errmsg->size, "invalid register %s for architecture %s",
                register_str(reg), arch_str(arch));
    }

    return result;
}

