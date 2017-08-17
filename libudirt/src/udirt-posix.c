/*
 * Copyright (c) 2011-2017, UDI Contributors
 * All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// UDI implementation specific to POSIX-compliant operating systems

// This needs to be included first because it sets feature macros
#include "udirt-platform.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <inttypes.h>

#include "udi.h"
#include "udirt.h"
#include "udirt-posix.h"

// macros
#define UDI_CONSTRUCTOR __attribute__((constructor))
#define CASE_TO_STR(x) case x: return #x

// testing
extern int testing_udirt(void) __attribute__((weak));

// constants
const char * const UDI_DS = "/";
const unsigned int DS_LEN = 1;
const char * const DEFAULT_UDI_ROOT_DIR = "/tmp/udi";
static const unsigned int PID_STR_LEN = 10;
static const unsigned int USER_STR_LEN = 25;

// file paths
static char *basedir_name;
static char *requestfile_name;
static char *responsefile_name;
static char *eventsfile_name;

// file handles
static int request_handle = -1;
static int response_handle = -1;
static int events_handle = -1;

// write/read permission fault handling
static int failed_si_code = 0;

// write failure handling
static int pipe_write_failure = 0;

// Continue handling
static int pass_signal = 0;

// Used to force threads into the library signal handler
extern int pthread_kill(pthread_t, int) __attribute__((weak));

// unexported prototypes
static int remove_udi_filesystem();

/**
 * Disables this library
 */
static void disable_debugging() {
    udi_enabled = 0;

    // Replace the library signal handler with the application signal handlers
    int i;
    for(i = 0; i < NUM_SIGNALS; ++i) {
        if ( signals[i] == SIGPIPE && pipe_write_failure ) continue;

        if ( real_sigaction(signals[i], &app_actions[i], NULL) != 0 ) {
            udi_printf("failed to reset signal handler for %d: %s\n",
                    signals[i], strerror(errno));
        }
    }

    udi_printf("%s\n", "Disabled debugging");
}

/**
 * @return non-zero if a single thread will be executing due to a library operation (such as
 * a memory access to a non-accessible address or a single-step event)
 */
static inline
int single_thread_executing() {
    return (is_performing_mem_access() || continue_bp != NULL);
}

/**
 * A UDI version of abort that performs some cleanup before calling abort
 */
void udi_abort(const char *file, unsigned int line) {
    udi_printf("udi_abort at %s[%d]\n", file, line);

    if ( real_sigaction ) {
        struct sigaction default_action;
        memset(&default_action, 0, sizeof(struct sigaction));
        default_action.sa_handler = SIG_DFL;

        // Need to avoid any user handlers
        real_sigaction(SIGABRT, (struct sigaction *)&default_action, NULL);

        disable_debugging();
    }

    abort();
}

/**
 * Performs handling necessary to handle a pipe write failure gracefully.
 */
static void handle_pipe_write_failure() {
    pipe_write_failure = 1;

    sigset_t set;

    if ( sigpending(&set) != 0 ) {
        udi_printf("failed to get pending signals: %s\n", strerror(errno));
        return;
    }

    if ( sigismember(&set, SIGPIPE) != 1 ) {
        udi_printf("%s\n", "SIGPIPE is not pending, cannot handle write failure");
        return;
    }

    sigset_t cur_set;
    if ( setsigmask(SIG_BLOCK, NULL, &cur_set) != 0 ) {
        udi_printf("failed to get current signals: %s\n", strerror(errno));
        return;
    }
    sigdelset(&set, SIGPIPE);

    sigsuspend(&set);
    if ( errno != EINTR ) {
        udi_printf("failed to wait for signal to be delivered: %s\n",
                strerror(errno));
        return;
    }

    pipe_write_failure = 0;
}

/**
 * Writes the specified event to the specified file descriptor
 *
 * @param fd the file descriptor
 * @param event the event to write
 *
 * @return 0 on success; non-zero otherwise
 */
int write_event_to_fd(int fd, udi_event_internal *event) {
    int errnum = 0;

    do {
        udi_event_type tmp_type = event->event_type;
        tmp_type = udi_event_type_hton(tmp_type);
        if ( (errnum = write_all(events_handle, &tmp_type,
                        sizeof(udi_event_type)) != 0 ) ) break;

        uint64_t thread_id = event->thread_id;
        thread_id = udi_uint64_t_hton(thread_id);
        if ( (errnum = write_all(events_handle, &thread_id,
                        sizeof(uint64_t))) != 0 ) break;

        udi_length tmp_length = event->length;
        tmp_length = udi_length_hton(tmp_length);
        if ( (errnum = write_all(events_handle, &tmp_length,
                        sizeof(udi_length))) != 0 ) break;

        if ( (errnum = write_all(events_handle, event->packed_data,
                        event->length)) != 0 ) break;
    }while(0);

    if ( errnum != 0 ) {
        udi_printf("failed to send event notification: %s\n",
                strerror(errnum));
    }

    if ( errnum == EPIPE ) {
        handle_pipe_write_failure();
    }

    return errnum;
}

/**
 * Writes the specified event to the library's event handle
 *
 * @param event the event to write
 *
 * @return 0 on success; non-zero otherwise
 */
int write_event(udi_event_internal *event) {
    return write_event_to_fd(events_handle, event);
}

/**
 * Translates the failed memory access code into an error
 * message
 *
 * @return the error message
 */
const char *get_mem_errstr() {
    switch(failed_si_code) {
        case SEGV_MAPERR:
            return "address not mapped in process";
        default:
            return "unknown memory error";
    }
}

void post_continue_hook(uint32_t sig_val) {
    if (!exiting) {
        pass_signal = sig_val;
        kill(getpid(), sig_val);

        udi_printf("continuing with signal %d\n", sig_val);
    }else{
        int remove_result = remove_udi_filesystem();
        if (remove_result != 0) {
            if (remove_result > 0) {
                udi_printf("failed to cleanup udi filesystem: %s\n", strerror(remove_result));
            }else{
                udi_printf("failed to cleanup udi filesystem\n");
            }
        }
    }
}

/**
 * Implementation of pre_mem_access hook. Unblocks SIGSEGV.
 *
 * @return the original signal set before SIGSEGV unblocked
 */
void *pre_mem_access_hook() {
    // Unblock the SIGSEGV to allow the write to complete
    sigset_t *original_set = (sigset_t *)udi_malloc(sizeof(sigset_t));

    if ( original_set == NULL ) {
        udi_printf("failed to allocate sigset_t: %s\n", strerror(errno));
        return NULL;
    }

    int result = 0;
    do {
        if ( setsigmask(SIG_BLOCK, NULL, original_set) != 0 ) {
            udi_printf("failed to change signal mask: %s\n", strerror(errno));
            result = -1;
            break;
        }

        sigset_t segv_set = *original_set;
        sigdelset(&segv_set, SIGSEGV);
        if ( setsigmask(SIG_SETMASK, &segv_set, original_set) != 0 ) {
            udi_printf("failed to unblock SIGSEGV: %s\n", strerror(errno));
            result = -1;
            break;
        }
    }while(0);

    if ( result ) {
        udi_free(original_set);
        original_set = NULL;
    }

    return original_set;
}

/**
 * Implementation of post mem access hook
 *
 * @param hook_arg the value returned from the pre mem access hook
 *
 * @return 0 on success; false otherwise
 */
int post_mem_access_hook(void *hook_arg) {

    sigset_t *original_set = (sigset_t *)hook_arg;

    int result = 0;
    if ( setsigmask(SIG_SETMASK, original_set, NULL) != 0 ) {
        udi_printf("failed to reset signal mask: %s\n", strerror(errno));
        result = -1;
    }

    udi_free(original_set);

    return result;
}

static
void write_error_response(udi_errmsg *errmsg,
                          udi_request_type_e req_type,
                          thread *thr)
{
    // explicitly ignore errors
    if (thr == NULL) {
        write_error_response(response_handle, req_type, errmsg);
    }else{
        write_error_response(thr->response_handle, req_type, errmsg);
    }
    udi_printf("Wrote error message '%s'\n", errmsg->msg);
}

/**
 * Waits for a request from the possible request handles
 *
 * @param thr the output parameter for the thread -- set to NULL if request is for process
 *
 * @return the read request
 */
static
int wait_for_request(thread **thr) {
    int max_fd = request_handle;

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(request_handle, &read_set);

    thread *iter = get_thread_list();
    while (iter != NULL) {
        if (!iter->dead) {
            FD_SET(iter->request_handle, &read_set);
            if ( iter->request_handle > max_fd ) {
                max_fd = iter->request_handle;
            }
        }
        iter = iter->next_thread;
    }

    do {
        fd_set changed_set = read_set;
        int result = select(max_fd + 1, &changed_set, NULL, NULL, NULL);

        if ( result == -1 ) {
            if ( errno == EINTR ) {
                udi_printf("%s\n", "select call interrupted, trying again");
                continue;
            }
            udi_printf("failed to wait for request: %s\n", strerror(errno));
        }else if ( result == 0 ) {
            udi_printf("%s\n", "select unexpectedly returned 0");
        }else{
            if ( FD_ISSET(request_handle, &changed_set) ) {
                *thr = NULL;
                return 0;
            }
            iter = get_thread_list();
            while (iter != NULL) {
                if ( FD_ISSET(iter->request_handle, &changed_set) ) {
                    *thr = iter;
                    return 0;
                }
                iter = iter->next_thread;
            }
        }
        break;
    }while(1);

    return -1;
}

/**
 * Wait for and request and process the request on reception.
 *
 * @param errmsg error message populate on error
 * @param thr populated by the thread that received the command
 *
 * @return request handler return code
 */
int wait_and_execute_command(udi_errmsg *errmsg, thread **thr) {
    int result = 0;

    int more_reqs = 1;
    while(more_reqs) {
        udi_printf("%s\n", "waiting for request");
        result = read_request(thr);
        if ( result != 0 ) {
            snprintf(errmsg->msg, errmsg->size, "%s", "failed to wait for request");
            udi_printf("%s\n", "failed to wait for request");
            result = REQ_ERROR;
            break;
        }

        if ( *thr == NULL ) {
            udi_printf("%s\n", "received process request");
            result = handle_process_request(request_handle, response_handle, errmsg);
        }else{
            udi_printf("received request for thread 0x%"PRIx64"\n", (*thr)->id);
            result = handle_thread_request((*thr)->request_handle,
                                           (*thr)->response_handle,
                                           *thr,
                                           errmsg);
        }

        if ( result != REQ_SUCCESS ) {
            write_error_response(errmsg, *thr);
            if ( result == REQ_FAILURE ) {
                more_reqs = 1;
            }else if ( result == REQ_ERROR ) {
                more_reqs = 0;
            }
        }else{
            more_reqs = 1;
        }

        if ( req->request_type == UDI_REQ_CONTINUE ) {
            more_reqs = 0;
        }
    }

    return result;
}

/**
 * Decodes the SIGSEGV using the specified arguments
 *
 * @param siginfo the siginfo argument passed to the signal handler
 * @param context the context argument passed to the signal handler
 * @param errmsg the errmsg populated on error
 *
 * @return the event decoded from the SIGSEGV
 */
static event_result decode_segv(const siginfo_t *siginfo, ucontext_t *context, udi_errmsg *errmsg) {
    event_result result;
    result.failure = 0;
    result.wait_for_request = 1;

    if ( is_performing_mem_access() ) {
        result.wait_for_request = 0;

        // if the error was due to permissions, change permissions temporarily
        // to allow mem access to complete
        if (siginfo->si_code == SEGV_ACCERR) {
            unsigned long mem_access_addr_ul = (unsigned long)get_mem_access_addr();

            // page align
            mem_access_addr_ul = mem_access_addr_ul & ~(sysconf(_SC_PAGESIZE)-1);

            // Note: this could cause unwanted side effects in the debuggee
            // because it could mask errors that the debuggee should encounter.
            // However, in order to handle this case, the protection for a page
            // must be queried from the OS, and currently there is not a
            // portable way to do this. Thus, the tradeoff was made in favor of
            // portability.
            if ( mprotect((void *)mem_access_addr_ul, get_mem_access_size(),
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0 ) 
            {
                result.failure = errno;
                udi_printf("failed to modify permissions for memory access: %s\n",
                        strerror(result.failure));
            }
        }else{
            udi_printf("address 0x%lx not mapped for process %d\n",
                    (unsigned long)siginfo->si_addr, getpid());
            result.failure = -1;
        }

        if (result.failure != 0) {
            set_pc(context, abort_mem_access());

            failed_si_code = siginfo->si_code;
        }

        if ( result.failure > 0 ) {
            strerror_r(result.failure, errmsg->msg, errmsg->size);
        }

        // If failures occurred, errors will be reported by code performing mem access
        result.failure = 0;
    }else{
        // TODO create event and send to debugger
    }

    return result;
}

static
int write_single_step_event(thread *thr) {
    udi_event_internal ss_event = create_event_single_step(thr->id);
    
    int result = write_event(&ss_event);

    if (result != 0) {
        udi_printf("failed to report single step event for thread 0x%"PRIx64"\n", thr->id);
    }

    return result;
}

/**
 * Handles the breakpoint event that occurred at the specified breakpoint
 *
 * @param thr the thread that hit the breakpoint
 * @param bp the breakpoint that triggered the event
 * @param context the context passed to the signal handler
 * @param errmsg the error message populated on error
 *
 * @return the result of decoding the event
 */
static
event_result decode_breakpoint(thread *thr, breakpoint *bp, ucontext_t *context, udi_errmsg *errmsg) {

    event_result result;
    result.failure = 0;
    result.wait_for_request = 1;

    rewind_pc(context);
    if (thr != NULL) {
        // make sure a read of the pc at a breakpoint returns the expected value
        rewind_pc(&thr->event_state.context); 
    }

    // Handle single step breakpoints
    if (thr != NULL && thr->single_step_bp == bp) {
        udi_printf("single step breakpoint at 0x%"PRIx64"\n", bp->address);

        int delete_result = delete_breakpoint(bp, errmsg);
        if (delete_result != 0) {
            udi_printf("failed to delete breakpoint at 0x%"PRIx64"\n", bp->address);
            result.failure = delete_result;
        }

        int write_result = write_single_step_event(thr);
        if ( write_result != 0 ) {
            result.failure = write_result;
        }

        thr->single_step_bp = NULL;

        return result;
    }

    // Before creating the event, need to remove the breakpoint and indicate 
    // that a breakpoint continue will be required after the next continue
    int remove_result = remove_breakpoint_for_continue(bp, errmsg);
    if ( remove_result != 0 ) {
        udi_printf("failed to remove breakpoint at 0x%"PRIx64"\n", bp->address);
        result.failure = remove_result;
        return result;
    }

    if ( continue_bp == bp ) {
        udi_printf("continue breakpoint at 0x%"PRIx64"\n", bp->address);

        result.wait_for_request = 0;
        continue_bp = NULL;

        int delete_result = delete_breakpoint(bp, errmsg);
        if ( delete_result != 0 ) {
            udi_printf("failed to delete breakpoint at 0x%"PRIx64"\n", bp->address);
            result.failure = delete_result;
        }

        // Need to re-install original breakpoint if it still should be in memory
        breakpoint *original_bp = find_breakpoint(last_bp_address);
        if ( original_bp != NULL ) {
            last_bp_address = 0;

            if ( original_bp->in_memory ) {
                // Temporarily reset the memory value
                original_bp->in_memory = 0;
                int install_result = install_breakpoint(original_bp, errmsg);
                if ( install_result != 0 ) {
                    udi_printf("failed to install breakpoint at 0x%"PRIx64"\n",
                            original_bp->address);
                    result.failure = install_result;
                }else{
                    udi_printf("re-installed breakpoint at 0x%"PRIx64"\n",
                            original_bp->address);
                }
            }
        }else{
            udi_printf("Not re-installing breakpoint at 0x%"PRIx64"\n", last_bp_address);
        }

        // Need to report single step event if this continue_bp was used for single stepping
        if (result.failure == 0 && thr != NULL && thr->single_step) {
            udi_printf("%s\n", "Using continue breakpoint as single step breakpoint");
            result.failure = write_single_step_event(thr);
            result.wait_for_request = 1;
        }

        return result;
    }

    unsigned long successor = get_ctf_successor(bp->address, errmsg, context);
    if (successor == 0) {
        udi_printf("failed to determine successor for instruction at 0x%"PRIx64"\n", bp->address);
        result.failure = 1;
        return result;
    }

    continue_bp = create_breakpoint(successor);
    if (continue_bp == NULL) {
        udi_printf("%s\n", "failed to create continue breakpoint");
        result.failure = 1;
        return result;
    }

    last_bp_address = bp->address;

    if ( is_event_breakpoint(bp) ) {
        udi_printf("handling event breakpoint at 0x%"PRIx64"\n", bp->address);
        return handle_event_breakpoint(bp, context, errmsg);
    }

    // Handle the case where this thread hit another thread-specific breakpoint
    // The thread should just be continued silently
    if ( bp->thread != NULL && bp->thread != thr ) {
        udi_printf("thread 0x%"PRIx64" hit breakpoint for thread 0x%"PRIx64"\n",
                bp->thread->id, thr->id);
        result.wait_for_request = 0;
        return result;
    }

    udi_printf("user breakpoint at 0x%"PRIx64"\n", bp->address);

    // create the event
    udi_event_internal brkpt_event = create_event_breakpoint(thr->id, bp->address);

    do {
        if ( brkpt_event.packed_data == NULL ) {
            result.failure = 1;
            break;
        }

        result.failure = write_event(&brkpt_event);

        udi_free(brkpt_event.packed_data);
    }while(0);

    if ( result.failure ) {
        udi_printf("failed to report breakpoint at 0x%"PRIx64"\n", bp->address);
    }

    return result;
}

/**
 * Decodes the trap
 *
 * @param thr the current thread
 * @param siginfo the siginfo passed to the signal handler
 * @param context the context passed to the signal handler
 * @param errmsg the error message populated on error
 */
static event_result decode_trap(thread *thr, const siginfo_t *siginfo, ucontext_t *context, udi_errmsg *errmsg) {
    event_result result;
    result.failure = 0;
    result.wait_for_request = 1;

    uint64_t trap_address = get_trap_address(context);

    // Check and see if it corresponds to a breakpoint
    breakpoint *bp = find_breakpoint(trap_address);

    if ( bp != NULL ) {
        udi_printf("breakpoint hit at 0x%"PRIx64"\n", trap_address);
        result = decode_breakpoint(thr, bp, context, errmsg);
    }else{
        // TODO create signal event
        result.failure = -1;
        result.wait_for_request = 0;
        snprintf(errmsg->msg, errmsg->size, "Failed to decode trap event at 0x%"PRIx64, trap_address);
    }

    return result;
}

/**
 * The signal handler entry point for the library
 *
 * See manpage for sigaction
 */
void signal_entry_point(int signal, siginfo_t *siginfo, void *v_context) {
    udi_errmsg errmsg;
    errmsg.size = ERRMSG_SIZE;
    errmsg.msg[ERRMSG_SIZE-1] = '\0';

    ucontext_t *context = (ucontext_t *)v_context;

    if ( pipe_write_failure && signal == SIGPIPE ) {
        udi_printf("%s\n", "Ignoring SIGPIPE due to previous library write failure");
        pipe_write_failure = 0;

        real_sigaction(signal, &app_actions[signal_map[signal % MAX_SIGNAL_NUM]], NULL);

        return;
    }

    if ( pass_signal != 0 ) {
        app_signal_handler(signal, siginfo, v_context);
        pass_signal = 0;
        return;
    }

    if (!udi_enabled && !is_performing_mem_access()) {
        udi_printf("UDI disabled, not handling signal %d at addr 0x%08lx\n", signal,
                (unsigned long)siginfo->si_addr);
        return;
    }

    udi_printf(">>> signal entry for 0x%"PRIx64"/%u with %d\n",
            get_user_thread_id(),
            get_kernel_thread_id(),
            signal);
    if ( is_performing_mem_access() ) {
        udi_printf("memory access at 0x%lx in progress\n", (unsigned long)get_mem_access_addr());
    }

    thread *thr = get_current_thread();

    if ( signal == THREAD_SUSPEND_SIGNAL && (thr == NULL || thr->suspend_pending == 1) ) {
        udi_printf("ignoring extraneous suspend signal for 0x%"PRIx64"/%u\n",
                get_user_thread_id(),
                get_kernel_thread_id());

        if ( thr != NULL ) thr->suspend_pending = 0;
        return;
    }

    if ( !single_thread_executing() ) {
        // save this signal event state to allow another thread to pass control to this
        // thread later on
        thr->event_state.signal = signal;
        thr->event_state.siginfo = *siginfo;
        thr->event_state.context = *context;
        thr->event_state.context_valid = 1;

        int block_result = block_other_threads();
        if ( block_result == -1 ) {
            udi_printf("%s\n", "failed to block other threads");
            udi_abort(__FILE__, __LINE__);
            return;
        }

        if ( block_result > 0 ) {
            memset(&(thr->event_state), 0, sizeof(signal_state));

            udi_printf("<<< waiting thread 0x%"PRIx64" exiting signal handler\n", get_user_thread_id());
            return;
        }
    }else if (continue_bp != NULL) {
        if (thr != NULL ) {
            thr->event_state.context = *context;
            thr->event_state.context_valid = 1;
        }
    }

    udi_printf("thread 0x%"PRIx64"/%u now handling signal %d\n",
            get_user_thread_id(),
            get_kernel_thread_id(),
            signal);
    if ( thr != NULL ) {
        thr->event_state.signal = 0;
    }

    // create event
    // Note: each decoder function will call write_event to avoid unnecessary
    // heap allocations

    event_result result;
    result.failure = 0;
    result.wait_for_request = 1;

    int request_error = 0;
    thread *request_thr = NULL;
    do {
        switch(signal) {
            case SIGSEGV:
                result = decode_segv(siginfo, context, &errmsg);
                break;
            case SIGTRAP:
                result = decode_trap(thr, siginfo, context, &errmsg);
                break;
            default: {
                udi_event_internal event = create_event_unknown(get_user_thread_id());

                result.failure = write_event(&event);
                break;
            }
        }

        if ( thr != NULL && thr->single_step ) {
            unsigned long pc = get_pc(context);
            unsigned long successor = get_ctf_successor(pc, &errmsg, context);
            if (successor == 0) {
                udi_printf("failed to determine successor for instruction at 0x%"PRIx64"\n",
                           (uint64_t)pc);
                result.failure = 1;
            }else{
                breakpoint *existing_bp = find_breakpoint(successor);

                // If it is a continue breakpoint, it will be used as a single step breakpoint. If it
                // is an event breakpoint or user breakpoint, no single step event will be
                // generated
                if ( existing_bp == NULL ) {
                    thr->single_step_bp = create_breakpoint(successor);
                    if (thr->single_step_bp == NULL) {
                        udi_printf("failed to create single step breakpoint at 0x%"PRIx64"\n",
                                (uint64_t) successor);
                        result.failure = 1;
                    }else{
                        thr->single_step_bp->thread = thr;
                        int install_result = install_breakpoint(thr->single_step_bp, &errmsg);
                        if (install_result != 0) {
                            udi_printf("failed to install single step breakpoint at 0x%"PRIx64"\n",
                                    (uint64_t) successor);
                            result.failure = install_result;
                        }
                    }
                }
            }
        }

        if ( result.failure != 0 ) {
            if ( result.failure > 0 ) {
                strncpy(errmsg.msg, strerror(result.failure), errmsg.size-1);
            }

            // Don't report any more errors after this event
            result.failure = 0;

            udi_event_internal event = create_event_error(get_user_thread_id(), &errmsg);

            // Explicitly ignore any errors -- no way to report them
            if ( event.packed_data != NULL ) {
                write_event(&event);
                udi_free(event.packed_data);
            }else{
                udi_printf("aborting due to event reporting failure: %s\n", errmsg.msg);
                udi_abort(__FILE__, __LINE__);
            }
        }
    
        // wait for command
        if ( result.wait_for_request ) {
            int req_result = wait_and_execute_command(&errmsg, &request_thr);
            if (req_result == REQ_SUCCESS) {
                result.failure = 0;
                request_error = 0;
            }else if (req_result == REQ_FAILURE) {
                result.failure = 1;
                request_error = 0;
            }else if (req_result == REQ_ERROR) {
                result.failure = 1;
                request_error = 1;
            }else{
                result.failure = 1;
                request_error = 1;
                strncpy(errmsg.msg, strerror(req_result), errmsg.size-1);
            }
        }
    }while(0);

    if ( result.failure ) {
        // A failed request most likely means the debugger is no longer around, so
        // don't try to send a response
        if ( !request_error ) {
            write_error_response(&errmsg, request_thr);
        }else{
            udi_printf("Aborting due to request failure: %s\n", errmsg.msg);
            udi_abort(__FILE__, __LINE__);
        }
    }else{
        // Cleanup before returning to user code
        if ( !single_thread_executing() ) {
            release_other_threads();
        }
    }

    udi_printf("<<< signal exit for 0x%"PRIx64"/%u with %d\n",
            get_user_thread_id(),
            get_kernel_thread_id(),
            signal);

    if (thr != NULL) {
        memset(&(thr->event_state), 0, sizeof(signal_state));
    }
}

/**
 * Enables debug logging if the environment specifies it
 */
static void enable_debug_logging() {
    // turn on debugging, if necessary
    if (getenv(UDI_DEBUG_ENV) != NULL) {
        udi_debug_on = 1;
        udi_printf("%s\n", "UDI rt debug logging enabled");
    }
}

/**
 * Performs any necessary global variable initialization
 */
static void global_variable_initialization() {
    // set allocator used for packing data
    udi_set_malloc(udi_malloc);
}

/**
 * Removes the udi filesystem for this process on exit
 */
static
int remove_udi_filesystem() {
    // TODO
    
    return 0;
}

/**
 * Creates the necessary elements for the udi filesystem
 */
static int create_udi_filesystem() {
    int errnum = 0;

    do {
        // get root directory
        if ((UDI_ROOT_DIR = getenv(UDI_ROOT_DIR_ENV)) == NULL) {
            UDI_ROOT_DIR = (char *)udi_malloc(strlen(DEFAULT_UDI_ROOT_DIR)+1);
            strncpy(UDI_ROOT_DIR, DEFAULT_UDI_ROOT_DIR,
                    strlen(DEFAULT_UDI_ROOT_DIR)+1);
        }

        // create the directory for this process
        size_t basedir_length = strlen(UDI_ROOT_DIR) + PID_STR_LEN 
            + USER_STR_LEN + 2*DS_LEN + 1;
        basedir_name = (char *)udi_malloc(basedir_length);
        if (basedir_name == NULL) {
            udi_printf("malloc failed: %s\n", strerror(errno));
            errnum = errno;
            break;
        }

        uid_t user_id = geteuid();
        struct passwd *passwd_info = getpwuid(user_id);
        if (passwd_info == NULL) {
            udi_printf("getpwuid failed: %s\n", strerror(errno));
            errnum = errno;
            break;
        }
    
        snprintf(basedir_name, basedir_length, "%s/%s/%d", UDI_ROOT_DIR,
                 passwd_info->pw_name, getpid());
        if (mkdir(basedir_name, S_IRWXG | S_IRWXU) == -1) {
            udi_printf("error creating basedir '%s': %s\n", basedir_name,
                    strerror(errno));
            errnum = errno;
            break;
        }

        // create the udi files
        size_t requestfile_length = basedir_length
                                    + strlen(REQUEST_FILE_NAME) + DS_LEN;
        requestfile_name = (char *)udi_malloc(requestfile_length);
        if (requestfile_name == NULL) {
            udi_printf("malloc failed: %s\n", strerror(errno));
            errnum = errno;
            break;
        }

        snprintf(requestfile_name, requestfile_length, "%s/%s/%d/%s",
                 UDI_ROOT_DIR, passwd_info->pw_name, getpid(), REQUEST_FILE_NAME);
        if (mkfifo(requestfile_name, S_IRWXG | S_IRWXU) == -1) {
            udi_printf("error creating request file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        size_t responsefile_length = basedir_length +
                               strlen(RESPONSE_FILE_NAME) + DS_LEN;
        responsefile_name = (char *)udi_malloc(responsefile_length);
        if (responsefile_name == NULL) {
            udi_printf("malloc failed: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        snprintf(responsefile_name, responsefile_length, "%s/%s/%d/%s",
                 UDI_ROOT_DIR, passwd_info->pw_name, getpid(), RESPONSE_FILE_NAME);
        if (mkfifo(responsefile_name, S_IRWXG | S_IRWXU) == -1) {
            udi_printf("error creating response file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        size_t eventsfile_length = basedir_length +
                             strlen(EVENTS_FILE_NAME) + DS_LEN;
        eventsfile_name = (char *)udi_malloc(eventsfile_length);
        if (eventsfile_name == NULL) {
            udi_printf("malloc failed: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        snprintf(eventsfile_name, eventsfile_length, "%s/%s/%d/%s",
                 UDI_ROOT_DIR, passwd_info->pw_name, getpid(), EVENTS_FILE_NAME);
        if (mkfifo(eventsfile_name, S_IRWXG | S_IRWXU) == -1) {
            udi_printf("error creating event file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }
    }while(0);

    return errnum;
}

/// barrier used to synchronize actions with other threads
static udi_barrier thread_barrier = { 0, -1, -1 };

/**
 * Initializes the thread synchronization mechanism
 *
 * @return 0 on success; non-zero on failure
 */
int initialize_thread_sync() {
    thread_barrier.sync_var = 0;

    if ( get_multithread_capable() ) {
        int control_pipe[2];
        if ( pipe(control_pipe) != 0 ) {
            udi_printf("failed to create sync pipe for rendezvous: %s\n", strerror(errno));
            return -1;
        }

        thread_barrier.read_handle = control_pipe[0];
        thread_barrier.write_handle = control_pipe[1];
    }else{
        thread_barrier.read_handle = -1;
        thread_barrier.write_handle = -1;
    }

    return 0;
}

/// the sentinel used to send signals to other threads
static const unsigned char sentinel = 0x21;

/**
 * The first thread that calls this function forces all other threads into the UDI signal handler,
 * which eventually routes to this function. 
 *
 * If a thread isn't the first thread calling this function, it will block until the library
 * decides the thread should continue executing, which is a combination of the user's desired
 * run state for a thread and the libraries desired run state for a thread.
 *
 * @return less than 0 if there is an error
 * @return 0 if the thread was the first thread or the thread should handle its event now
 * @return greater than 0 if the thread was not the first thread
 */
int block_other_threads() {

    int result = 0;
    if (get_multithreaded()) {
        thread *thr = get_current_thread();
        if ( thr == NULL ) {
            udi_printf("found unknown thread 0x%"PRIx64"\n", get_user_thread_id());
            return -1;
        }

        // Determine whether this is the first thread or not
        unsigned int sync_var = __sync_val_compare_and_swap(&(thread_barrier.sync_var), 0, 1);
        if (sync_var == 0) {
            thr->control_thread = 1;
            udi_printf("thread 0x%"PRIx64" is the control thread\n", thr->id);

            int num_suspended = 0;
            thread *iter = get_thread_list();
            while (iter != NULL) {
                if ( iter != thr ) {
                    iter->control_thread = 0;

                    // only force running threads into the signal handler, suspended threads are
                    // already in the signal handler
                    if (iter->ts != UDI_TS_SUSPENDED) {
                        if ( pthread_kill((pthread_t)iter->id, THREAD_SUSPEND_SIGNAL) != 0 ) {
                            udi_printf("failed to send signal to 0x%"PRIx64"\n",
                                    iter->id);
                            return -1;
                        }
                        udi_printf("thread 0x%"PRIx64" sent suspend signal %d to thread 0x%"PRIx64"\n",
                                thr->id,
                                THREAD_SUSPEND_SIGNAL,
                                iter->id);
                        num_suspended++;
                    }else{
                        udi_printf("thread 0x%"PRIx64" already suspended, not signalling\n",
                                iter->id);
                    }
                }
                iter = iter->next_thread;
            }

            __sync_synchronize(); // global state updated, issue full memory barrier

            // wait for the other threads to reach this function
            int i;
            for (i = 0; i < num_suspended; ++i) {
                unsigned char trigger;
                if ( read(thread_barrier.read_handle, &trigger, 1) != 1 ) {
                    udi_printf("failed to read trigger from pipe: %s\n", strerror(errno));
                    return -1;
                }

                if ( trigger != sentinel ) {
                    udi_abort(__FILE__, __LINE__);
                    return -1;
                }
            }
            udi_printf("thread 0x%"PRIx64" blocked other threads\n", thr->id);
        }else{
            // signal that thread is now waiting to be released
            if ( write(thread_barrier.write_handle, &sentinel, 1) != 1 ) {
                udi_printf("failed to write trigger to pipe: %s\n", strerror(errno));
                return -1;
            }

            udi_printf("thread 0x%"PRIx64" waiting to be released (pending signal = %d)\n", thr->id,
                    thr->event_state.signal);

            // Indicate that another suspend signal is pending if the reason for the thread
            // to enter the handler was not triggered by the library
            if ( thr->event_state.signal != THREAD_SUSPEND_SIGNAL ) {
                thr->suspend_pending = 1;
                udi_printf("thread 0x%"PRIx64" has a suspend signal pending\n", thr->id);
            }else{
                thr->suspend_pending = 0;
            }

            unsigned char trigger;
            if ( read(thr->control_read, &trigger, 1) != 1 ) {
                udi_printf("failed to read control trigger from pipe: %s\n", strerror(errno));
                return -1;
            }

            if ( trigger != sentinel ) {
                udi_abort(__FILE__, __LINE__);
                return -1;
            }
        }

        // if this thread has become the control thread, act accordingly
        result = (thr->control_thread == 1) ? 0 : 1;
    }

    return result;
}

/**
 * Releases the other threads that are blocked in block_other_threads
 *
 * Marks any threads that were created during this request handling
 *
 * @return 0 on success
 * @return non-zero on failure
 */
int release_other_threads() {
    if (get_multithread_capable()) {
        thread *thr = get_current_thread();
        // it is okay if this thr is NULL -- this occurs when a thread hits the death breakpoint
        
        thread *iter = get_thread_list();
        // determine if an event for another thread is pending
        while (iter != NULL) {
            // XXX: there is a known race here where a thread is sent a THREAD_SUSPEND_SIGNAL by
            // another source external to the library but at the same time, the library sends the same
            // signal to the thread. The result is that there is no way to handle the externally
            // sourced signal.
            if ( iter != thr && iter->event_state.signal != THREAD_SUSPEND_SIGNAL && iter->event_state.signal != 0 ) break;
            iter = iter->next_thread;
        }

        if ( iter != thr && iter != NULL ) {
            // Found another event that needs to be handled
            
            if ( thr != NULL ) __sync_val_compare_and_swap(&(thr->control_thread), 1, 0);

            __sync_val_compare_and_swap(&(iter->control_thread), 0, 1);

            if ( write(iter->control_write, &sentinel, 1) != 1 ) {
                udi_printf("failed to write control trigger to pipe: %s\n", strerror(errno));
                return -1;
            }

            if ( thr != NULL ) {
                udi_printf("thread 0x%"PRIx64" waiting to be released after transferring control to thread 0x%"PRIx64"\n",
                        thr->id, iter->id);
                unsigned char trigger;
                if ( read(thr->control_read, &trigger, 1) != 1 ) {
                    udi_printf("failed to read control trigger from pipe: %s\n", strerror(errno));
                    return -1;
                }

                if ( trigger != sentinel ) {
                    udi_abort(__FILE__, __LINE__);
                    return -1;
                }
            }
        }else{
            // clear "lock" for future entrances to block_other_threads
            //
            // Note: it's possible that the sync var is already 0 when the first thread was created
            // -- just ignore this case as the below code handles this case correctly
            __sync_val_compare_and_swap(&(thread_barrier.sync_var), 1, 0);

            // release the other threads, if they should be running
            iter = get_thread_list();
            while ( iter != NULL ) {
                if ( iter != thr && iter->ts == UDI_TS_RUNNING ) {
                    if ( iter->alive ) {
                        if ( write(iter->control_write, &sentinel, 1) != 1 ) {
                            udi_printf("failed to write control trigger to pipe: %s\n",
                                    strerror(errno));
                            return -1;
                        }
                    }else{
                        udi_printf("Marking 0x%"PRIx64" alive\n", iter->id);
                        iter->alive = 1;
                    }
                }
                iter = iter->next_thread;
            }

            udi_printf("thread 0x%"PRIx64" released other threads\n", get_user_thread_id());


            if ( thr != NULL && thr->ts == UDI_TS_SUSPENDED ) {
                // If the current thread was suspended in this signal handler call, block here
                udi_printf("thread 0x%"PRIx64" waiting to be released after releasing threads\n", thr->id);

                unsigned char trigger;
                if ( read(thr->control_read, &trigger, 1) != 1 ) {
                    udi_printf("failed to read control trigger from pipe: %s\n", strerror(errno));
                    return -1;
                }

                if ( trigger != sentinel ) {
                    udi_abort(__FILE__, __LINE__);
                    return -1;
                }
            }
        }
    }

    return 0;
}

/**
 * Allocates and populates a string with the thread directory
 *
 * @param thr the thread
 *
 * @return the string
 */ 
static
char *get_thread_dir(thread *thr) {
    char subdir_name[32];

    snprintf(subdir_name, 32, "%"PRIx64, thr->id);

    size_t dir_length = strlen(basedir_name) + DS_LEN + strlen(subdir_name) + 1;
    char *thread_dir = (char *)udi_malloc(dir_length);
    if (thread_dir == NULL) {
        udi_printf("malloc failed: %s\n", strerror(errno));
        return NULL;
    }

    snprintf(thread_dir, dir_length, "%s/%s", basedir_name, subdir_name);
    return thread_dir;
}

/**
 * Allocates and populates a string with the thread directory
 *
 * @param thr the thread
 * @param thread_dir the thread directory
 * @param filename the filename
 *
 * @return the string
 */
static
char *get_thread_file(thread *thr, char *thread_dir, const char *filename) {
    size_t file_length = strlen(thread_dir) + DS_LEN + strlen(filename) + 1;
    char *thread_file = (char *)udi_malloc(file_length);
    if (thread_file == NULL) {
        udi_printf("malloc failed: %s\n", strerror(errno));
        return NULL;
    }

    snprintf(thread_file, file_length, "%s/%s", thread_dir, filename);
    return thread_file;
}

/**
 * Called by the thread support implementation
 *
 * @param thr the thread structure for the created thread
 * @param errmsg the error message
 *
 * @return 0 on success; non-zero on failure
 */
int thread_create_callback(thread *thr, udi_errmsg *errmsg) {

    // create the filesystem elements
    char *thread_dir = NULL, *response_file = NULL, *request_file = NULL;

    int result = 0;
    do {
        thread_dir = get_thread_dir(thr);
        if (thread_dir == NULL) {
            result = -1;
            break;
        }

        if (mkdir(thread_dir, S_IRWXG | S_IRWXU) == -1) {
            snprintf(errmsg->msg, errmsg->size, "failed to create directory %s: %s", 
                    thread_dir, strerror(errno));
            result = -1;
            break;
        }

        response_file = get_thread_file(thr, thread_dir, RESPONSE_FILE_NAME);
        if (response_file == NULL) {
            result = -1;
            break;
        }

        request_file = get_thread_file(thr, thread_dir, REQUEST_FILE_NAME);
        if (request_file == NULL) {
            result = -1;
            break;
        }

        if (mkfifo(request_file, S_IRWXG | S_IRWXU) == -1) {
            snprintf(errmsg->msg, errmsg->size, "failed to create request pipe %s: %s", 
                    request_file, strerror(errno));
            result = -1;
            break;
        }

        if (mkfifo(response_file, S_IRWXG | S_IRWXU) == -1) {
            snprintf(errmsg->msg, errmsg->size, "failed to create response pipe %s: %s", 
                    response_file, strerror(errno));
            result = -1;
            break;
        }
    }while(0);

    if (result != 0) {
        udi_printf("%s\n", errmsg->msg);
    }

    udi_free(thread_dir);
    udi_free(response_file);
    udi_free(request_file);

    return result;
}

/**
 * Performs the handshake with the debugger after the creation of the thread files
 *
 * @param thr the thread structure for the created thread
 * @param errmsg the error message
 *
 * @return 0 on success; non-zero on failure
 */
int thread_create_handshake(thread *thr, udi_errmsg *errmsg) {

    char *thread_dir = NULL, *response_file = NULL, *request_file = NULL;
    int result = 0;

    do {
        thread_dir = get_thread_dir(thr);
        if (thread_dir == NULL) {
            result = -1;
            break;
        }

        response_file = get_thread_file(thr, thread_dir, RESPONSE_FILE_NAME);
        if (response_file == NULL) {
            result = -1;
            break;
        }

        request_file = get_thread_file(thr, thread_dir, REQUEST_FILE_NAME);
        if (request_file == NULL) {
            result = -1;
            break;
        }

        if ( (thr->request_handle = open(request_file, O_RDONLY)) == -1 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to open %s: %s", request_file, strerror(errno));
            result = -1;
            break;
        }

        udi_request *init_request = read_request_from_fd(thr->request_handle);
        if (init_request == NULL) {
            snprintf(errmsg->msg, errmsg->size, "failed to read init request");
            result = -1;
            break;
        }

        if (init_request->request_type != UDI_REQ_INIT) {
            udi_printf("%s", "invalid request type, proceeding anyways");
        }

        free_request(init_request);

        if ( (thr->response_handle = open(response_file, O_WRONLY)) == -1 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to open %s: %s", response_file, strerror(errno));
            result = -1;
            break;
        }

        udi_response init_response = create_response_init(get_protocol_version(),
                get_architecture(),
                get_multithread_capable(),
                get_user_thread_id());

        if ( init_response.packed_data == NULL ) {
            snprintf(errmsg->msg, errmsg->size, "failed to create init response: %s\n",
                    strerror(errno));
            result = -1;
            break;
        }

        result = write_response_to_fd(thr->response_handle, &init_response);
        udi_free(init_response.packed_data);

        if ( result != 0 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to write init response");
        }
    }while(0);

    if (result != 0) {
        udi_printf("%s\n", errmsg->msg);
    }

    udi_free(thread_dir);
    udi_free(response_file);
    udi_free(request_file);

    return result;
}

/**
 * Called by the thread support implementation before thread event is published
 *
 * @param thr the thread structure for the dead thread
 * @param errmsg the error message
 *
 * @return 0 on success; non-zero on failure
 */
int thread_death_callback(thread *thr, udi_errmsg *errmsg) {
    thr->dead = 1;
    udi_printf("thread 0x%"PRIx64" marked dead\n", thr->id);

    // close the response file
    if ( close(thr->response_handle) != 0 ) {
        snprintf(errmsg->msg, errmsg->size, "failed to close response handle for thread 0x%"PRIx64": %s",
                thr->id, strerror(errno));
        udi_printf("%s\n", errmsg->msg);
        return -1;
    }

    return 0;
}

/**
 * Called before the process is continued after a thread death event was published
 *
 * @param thr the thread structure for the dead thread
 * @param errmsg the error message
 *
 * @return 0 on success; non-zero on failure
 */
static
int thread_death_handshake(thread *thr, udi_errmsg *errmsg) {

    if (!thr->dead) {
        snprintf(errmsg->msg, errmsg->size, "thread 0x%"PRIx64" is not dead, not completing handshake",
                thr->id);
        udi_printf("%s\n", errmsg->msg);
        return -1;
    }

    // close the request file
    if ( close(thr->request_handle) != 0 ) {
        snprintf(errmsg->msg, errmsg->size, "failed to close request handle for thread 0x%"PRIx64": %s",
                thr->id, strerror(errno));
        udi_printf("%s\n", errmsg->msg);
        return -1;
    }

    // delete the pipes and the thread directory
    char *thread_dir = NULL, *response_file = NULL, *request_file = NULL;
    int result = 0;
    do {
        thread_dir = get_thread_dir(thr);
        if (thread_dir == NULL) {
            result = -1;
            break;
        }

        response_file = get_thread_file(thr, thread_dir, RESPONSE_FILE_NAME);
        if (response_file == NULL) {
            result = -1;
            break;
        }

        if ( unlink(response_file) != 0 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to unlink %s: %s",
                    response_file, strerror(errno));
            result = -1;
            break;
        }

        request_file = get_thread_file(thr, thread_dir, REQUEST_FILE_NAME);
        if (request_file == NULL) {
            result = -1;
            break;
        }

        if ( unlink(request_file) != 0 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to unlink %s: %s",
                    request_file, strerror(errno));
            result = -1;
            break;
        }

        if ( rmdir(thread_dir) != 0 ) {
            snprintf(errmsg->msg, errmsg->size, "failed to rmdir %s: %s",
                    thread_dir, strerror(errno));
            result = -1;
            break;
        }
    }while(0);

    if ( result != 0 ) {
        udi_printf("%s\n", errmsg->msg);
    }

    udi_free(thread_dir);
    udi_free(response_file);
    udi_free(request_file);

    destroy_thread(thr);

    return 0;
}

/**
 * Performs the initiation handshake with the debugger.
 *
 * @param output_enabled set if an error can be reported to the debugger
 * @param errmsg the error message populated on error
 *
 * @return 0 on success; non-zero on failure
 */
static 
int handshake_with_debugger(int *output_enabled, udi_errmsg *errmsg) {
    int errnum = 0;

    do {
        if ((request_handle = open(requestfile_name, O_RDONLY))
                == -1 ) {
            udi_printf("error opening request file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        udi_request *init_request = read_request_from_fd(request_handle);
        if ( init_request == NULL ) {
            snprintf(errmsg->msg, errmsg->size, "%s", 
                    "failed reading init request");
            udi_printf("%s\n", "failed reading init request");
            errnum = -1;
            break;
        }
        
        if ( init_request->request_type != UDI_REQ_INIT ) {
            udi_printf("%s\n",
                    "invalid init request received, proceeding anyways...");
        }

        free_request(init_request);

        if ((response_handle = open(responsefile_name, O_WRONLY))
                == -1 ) {
            udi_printf("error open response file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }
        *output_enabled = 1;

        thread *thr = create_initial_thread();
        if (thr == NULL) {
            udi_printf("%s\n", "failed to create initial thread");
            errnum = -1;
            break;
        }

        if ( (errnum = thread_create_callback(thr, errmsg)) != 0 ) {
            udi_printf("failed to create thread-specific files: %s\n", errmsg->msg);
            break;
        }

        if ((events_handle = open(eventsfile_name, O_WRONLY))
                == -1 ) {
            udi_printf("error open response file fifo: %s\n",
                       strerror(errno));
            errnum = errno;
            break;
        }

        // create the init response
        udi_response init_response = create_response_init(get_protocol_version(),
                get_architecture(),
                get_multithread_capable(),
                get_user_thread_id());

        if ( init_response.packed_data == NULL ) {
            udi_printf("failed to create init response: %s\n",
                    strerror(errno));
            errnum = errno;
            break;
        }

        errnum = write_response(&init_response);
        if ( errnum ) {
            udi_printf("%s\n", "failed to write init response");
            *output_enabled = 0;
        }

        udi_free(init_response.packed_data);

        if ( (errnum = thread_create_handshake(thr, errmsg)) != 0 ) {
            udi_printf("failed to complete thread create handshake: %s\n", errmsg->msg);
            break;
        }

        // after sending init response, any debugging operations are valid
        udi_enabled = 1;

    }while(0);

    return errnum;
}


/**
 * Re-initializes the process, currently used to initialize child produced by a fork
 */
void reinit_udi_rt() {
    // TODO
}

/** The entry point for initialization declaration */
void init_udi_rt() UDI_CONSTRUCTOR;

/**
 * The entry point for initialization
 */
void init_udi_rt() {
    udi_errmsg errmsg;
    errmsg.size = ERRMSG_SIZE;
    errmsg.msg[ERRMSG_SIZE-1] = '\0';

    int errnum = 0, output_enabled = 0;

    enable_debug_logging();

    if ( testing_udirt != NULL ) return;

    global_variable_initialization();
   
    thread *request_thr = NULL;
    sigset_t original_set;
    do {
        sigset_t block_set;
        sigfillset(&block_set);

        // Block any signals during initialization
        if ( setsigmask(SIG_SETMASK, &block_set, &original_set) 
                == -1 ) 
        {
            errnum = errno;
            udi_printf("failed to block all signals: %s\n", strerror(errnum));
            break;
        }

        if ( (errnum = locate_wrapper_functions(&errmsg)) != 0 ) {
            udi_printf("%s\n", "failed to locate wrapper functions");
            break;
        }

        if ( (errnum = initialize_pthreads_support(&errmsg))
                != 0 )
        {
            udi_printf("%s\n", "failed to initialize pthreads support");
            break;
        }

        if ( (errnum = initialize_thread_sync()) != 0 ) {
            udi_printf("%s\n", "failed to initialize thread sync");
            break;
        }

        if ( (errnum = setup_signal_handlers()) != 0 ) {
            udi_printf("%s\n", "failed to setup signal handlers");
            break;
        }

        if ( (errnum = install_event_breakpoints(&errmsg)) != 0 ) {
            udi_printf("%s\n", "failed to install event breakpoints");
            break;
        }

        if ( (errnum = create_udi_filesystem()) != 0 ) {
            udi_printf("%s\n", "failed to create udi filesystem");
            break;
        }

        if ( (errnum = handshake_with_debugger(&output_enabled, &errmsg) != 0) ) {
            udi_printf("%s\n", "failed to complete handshake with debugger");
            break;
        }

        if ( (errnum = wait_and_execute_command(&errmsg, &request_thr)) != REQ_SUCCESS ) {
            udi_printf("%s\n", "failed to wait for initial command");
            break;
        }
    } while(0);

    if (errnum > 0) {
        strerror_r(errnum, errmsg.msg, errmsg.size-1);
    }

    if (errnum != 0) {
        udi_enabled = 0;

        if(output_enabled) {
            // explicitly don't worry about return
            write_error_response(&errmsg, request_thr);
        }

        udi_printf("%s\n", "Initialization failed");
        udi_abort(__FILE__, __LINE__);
    }else{
        udi_printf("%s\n", "Initialization completed");
    }

    // Explicitly ignore errors
    setsigmask(SIG_SETMASK, &original_set, NULL);
}

int read_all(int fd, void *dest, size_t length) 
{
    size_t total = 0;
    while (total < length) {
        ssize_t num_read = read(fd, ((unsigned char*)dest) + total, 
                length - total);

        if ( num_read == 0 ) {
            // Treat end-of-file as a separate error
            return -1;
        }

        if (num_read < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        total += num_read;
    }

    return 0;
}

int write_all(int fd, void *src, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t num_written = write(fd, ((unsigned char *)src) + total, 
                length - total);
        if ( num_written < 0 ) {
            if ( errno == EINTR ) continue;
            return errno;
        }

        total += num_written;
    }

    return 0;
}
