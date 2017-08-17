/*
 * Copyright (c) 2011-2017, UDI Contributors
 * All rights reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// UDI debuggee implementation common between all platforms

#ifndef _UDI_RT_H
#define _UDI_RT_H 1

#include <stdio.h>
#include <stdint.h>

#include "udi.h"
#include "udirt-platform.h"

#ifdef __cplusplus
extern "C" {
#endif

// Macros //
#define member_sizeof(s,m) ( sizeof( ((s *)0)->m ) )

// global variables //

// platform independent variables and constants
extern const char * const UDI_ROOT_DIR_ENV;
extern const char * const REQUEST_FILE_NAME;
extern const char * const RESPONSE_FILE_NAME;
extern const char * const EVENTS_FILE_NAME;
extern const char * const UDI_DEBUG_ENV;
extern const uint64_t UDI_SINGLE_THREAD_ID;

extern int udi_enabled;
extern int udi_debug_on;

// platform specific variables and constants
extern const char * const DEFAULT_UDI_ROOT_DIR;
extern const char * const UDI_DS;
extern const unsigned int DS_LEN;

extern char *UDI_ROOT_DIR;

// General platform-specific functions
void udi_abort(const char *file, unsigned int line);
int read_from(udirt_fd fd, uint8_t *dst, size_t length);
int write_to(udirt_fd fd, const uint8_t *src, size_t length);

// UDI RT internal malloc
void udi_free(void *ptr);
void *udi_malloc(size_t length);
void *udi_calloc(size_t count, size_t size);
void *udi_realloc(void *ptr, size_t length);

// helper functions
const char *request_type_str(udi_request_type_e req_type); 
const char *event_type_str(udi_event_type_e event_type);
const char *arch_str(udi_arch_e arch);
const char *register_str(udi_register_e reg);

#define ERRMSG_SIZE 4096
typedef struct {
    char msg[ERRMSG_SIZE];
    unsigned int size;
} udi_errmsg;

// threads
typedef struct thread_struct thread;
int thread_death_handshake(thread *thr, udi_errmsg *errmsg);
int get_num_threads();
int get_multithread_capable();
int get_multithreaded();
thread *get_thread_list();
thread *get_next_thread(thread *thr);
thread *get_current_thread();
int is_thread_dead(thread *thr);

// request handling
udi_version_e get_protocol_version();

void init_req_handling();
int handle_process_request(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg);
int handle_thread_request(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg);

// reading and writing debuggee memory
void *get_mem_access_addr();
size_t get_mem_access_size();

unsigned long abort_mem_access();
int is_performing_mem_access();

void *pre_mem_access_hook();
int post_mem_access_hook(void *hook_arg);

int read_memory(void *dest, const void *src, size_t num_bytes, udi_errmsg *errmsg);
int write_memory(void *dest, const void *src, size_t num_bytes, udi_errmsg *errmsg);

const char *get_mem_errstr();

// disassembly interface
unsigned long get_ctf_successor(unsigned long pc, udi_errmsg *errmsg, void *context);

// register interface
int get_register(udi_arch_e arch, udi_register_e reg, udi_errmsg *errmsg, uint64_t *value, 
        const void *context);
int set_register(udi_arch_e arch, udi_register_e reg, udi_errmsg *errmsg, uint64_t value,
        void *context);
int is_gp_register(udi_arch_e arch, udi_register_e reg);
int is_fp_register(udi_arch_e arch, udi_register_e reg);

// breakpoint handling
typedef struct breakpoint_struct {
    unsigned char saved_bytes[8];
    uint64_t address;
    unsigned char in_memory;
    thread *thread; // NULL if the breakpoint is set for all threads
    struct breakpoint_struct *next_breakpoint;
} breakpoint;

breakpoint *create_breakpoint(uint64_t breakpoint_addr);

int install_breakpoint(breakpoint *bp, udi_errmsg *errmsg);
int remove_breakpoint(breakpoint *bp, udi_errmsg *errmsg);
int remove_breakpoint_for_continue(breakpoint *bp, udi_errmsg *errmsg);
int delete_breakpoint(breakpoint *bp, udi_errmsg *errmsg);
breakpoint *find_breakpoint(uint64_t breakpoint_addr);

// architecture specific breakpoint handling
int write_breakpoint_instruction(breakpoint *bp, udi_errmsg *errmsg);
int write_saved_bytes(breakpoint *bp, udi_errmsg *errmsg);
udi_arch_e get_architecture();

// continue handling //

/** The breakpoint used to single step from a user breakpoint */
extern breakpoint *continue_bp;

/**
 * A hook ran after the continue response has been sent
 *
 * @param sig_val the value of the signal to continue the process with
 */
void post_continue_hook(uint32_t sig_val);

// error logging
#define udi_printf(format, ...) \
    do {\
        if( udi_debug_on ) {\
            fprintf(stderr, "%s[%d]: " format, __FILE__, __LINE__,\
                    ## __VA_ARGS__);\
        }\
    }while(0)

#ifdef __cplusplus
} // extern C
#endif

#endif
