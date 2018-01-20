/*
 * Copyright (c) 2011-2018, UDI Contributors
 * All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "udirt-platform.h"

#include <sys/syscall.h>
#include <unistd.h>

#include "udirt-posix.h"

void (*pthreads_create_event)(void) = NULL;
void (*pthreads_death_event)(void) = NULL;

uint64_t finalize_thread(udi_errmsg *errmsg) {
    return get_user_thread_id();
}

int initialize_pthreads_support(udi_errmsg *errmsg) {
    return 0;
}

uint64_t get_kernel_thread_id() {
    return (uint64_t)syscall(SYS_thread_selfid);
}

uint64_t initialize_thread(udi_errmsg *errmsg) {
    return -1;
}
