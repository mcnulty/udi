/*
 * Copyright (c) 2011-2018, UDI Contributors
 * All rights reserved.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// UDI debuggee implementation common between all platforms

#ifndef _UDI_RT_POSIX_H
#define _UDI_RT_POSIX_H 1

#include <ucontext.h>
#include <signal.h>
#include <sys/types.h>
#include <string.h>
#include <dlfcn.h>

#include "udirt.h"

#ifdef __cplusplus
extern "C" {
#endif

// syscall events
typedef int (*sigaction_type)(int, const struct sigaction *, 
        struct sigaction *);
typedef pid_t (*fork_type)(void);
typedef int (*execve_type)(const char *, char *const *, char *const *);
typedef void (* (*signal_type)(int, void (*handler)(int)))(int);

extern sigaction_type real_sigaction;
extern fork_type real_fork;
extern execve_type real_execve;

int locate_wrapper_functions(udi_errmsg *errmsg);
int install_event_breakpoints(udi_errmsg *errmsg);

int wait_and_execute_command(udi_errmsg *errmsg, thread **thr);

// re-initialize a process after fork
void reinit_udirt();

// exit event handling

/** indicates that the process will exit on the next continue request */
extern int exiting;

/**
 * Determines the argument to the exit function, given the context at which the exit breakpoint
 * was hit
 *
 * @param context the current context
 * @param errmsg the error message populated by the memory access
 *
 * @return the result
 */
int get_exit_argument(const ucontext_t *context, int *status, udi_errmsg *errmsg);

// library wrapping
extern void *UDI_RTLD_NEXT;

// breakpoint handling //

/**
 * Given the context, calculates the address at which a trap occurred at.
 *
 * @param context the context containing the current PC value
 *
 * @return the computed address
 */
uint64_t get_trap_address(const ucontext_t *context);

/**
 * Given the context, sets the pc to the supplied value
 *
 * @param context the context containing the current PC value
 * @param pc the new pc value
 */
void set_pc(ucontext_t *context, unsigned long pc);

// signal handling
int setup_signal_handlers();
int uninstall_signal_handlers();
void app_signal_handler(int signal, siginfo_t *siginfo, void *v_context);
void signal_entry_point(int signal, siginfo_t *siginfo, void *v_context);

// write failure handling
extern int pipe_write_failure;

// pthreads support //

// signal handling
typedef struct signal_state_struct {
    int signal;
    siginfo_t siginfo;
    ucontext_t context;
    int context_valid;
} signal_state;
extern int THREAD_SUSPEND_SIGNAL;

struct thread_struct {
    uint64_t id;
    udi_thread_state_e ts;
    int alive;
    int dead;
    int request_handle;
    int response_handle;
    int control_write;
    int control_read;
    int control_thread;
    int suspend_pending;
    int single_step;
    breakpoint *single_step_bp;
    signal_state event_state;
    struct thread_struct *next_thread;
};

int setsigmask(int how, const sigset_t *new_set, sigset_t *old_set);

/**
 * @return the kernel thread id for the currently executing thread
 */
uint64_t get_kernel_thread_id();

// thread synchronization
typedef struct udi_barrier_struct {
    unsigned int sync_var;
    int read_handle;
    int write_handle;
} udi_barrier;
int initialize_thread_sync();
int block_other_threads();
int release_other_threads();

// thread events
extern void (*pthreads_create_event)(void);
extern void (*pthreads_death_event)(void);

/**
 * Initializes pthreads support
 *
 * @param errmsg the errmsg populated on error
 *
 * @return 0 on success; non-zero on failure
 */
int initialize_pthreads_support(udi_errmsg *errmsg);

int install_thread_event_breakpoints(udi_errmsg *errmsg);
int is_thread_event_breakpoint(breakpoint *bp);
int handle_thread_event_breakpoint(breakpoint *bp,
                                   const ucontext_t *context,
                                   udi_errmsg *errmsg);

thread *create_initial_thread();
int thread_create_callback(thread *thr, udi_errmsg *errmsg);
int thread_create_handshake(thread *thr, udi_errmsg *errmsg);

/**
 * Initializes the newly created thread
 *
 * @param errmsg the error message (populated on error)
 *
 * @return the tid on success; 0 on failure
 */
uint64_t initialize_thread(udi_errmsg *errmsg);

int thread_death_callback(thread *thr, udi_errmsg *errmsg);

/**
 * Determines the thread that is in the process of being finalized
 *
 * @param errmsg the error message
 *
 * @return the tid for the finalized thread, 0 on error
 */
uint64_t finalize_thread(udi_errmsg *errmsg);

void destroy_thread(thread *thr);

#ifdef __cplusplus
} // extern C
#endif

#endif
