/*
 * Copyright (c) 2011-2017, UDI Contributors
 * All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * UDI request handling
 *
 * @file udirt-req.c
 */

#include "udirt.h"

const int REQ_SUCCESS = 0;
const int REQ_ERROR = -1;
const int REQ_FAILURE = -2;

int handle_process_request(udirt_fd fd, udi_errmsg *errmsg) {
    // Read the request type data item
    
    // Read the request data (if any)
    
    // Execute the request
}

int handle_thread_request(udirt_fd fd, thread *thr, udi_errmsg *errmsg) {

}
