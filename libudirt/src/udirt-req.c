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

#include <errno.h>
#include <string.h>

#include "cbor.h"

#include "udirt.h"

struct msg_item {
    const char *key;
    struct cbor_callbacks callbacks;
};

struct msg_config {
    int num_items;
    const struct msg_item *items;
};

struct cbor_read_state {
    void *ctx;
    int done;
};

void init_req_handling()
{
#if CBOR_CUSTOM_ALLOC
    cbor_set_allocs(udi_malloc, udi_realloc, udi_free);
#else
#error libcbor custom allocated not supported
#endif
}

static
int read_cbor_items(udirt_fd fd,
                    void *ctx,
                    const struct cbor_callbacks *callbacks,
                    udi_errmsg *errmsg) {

    struct cbor_read_state state = {
        .ctx = ctx,
        .done = 0
    };
    int result = 0;
    int cbor_done = 0;
    uint8_t *buffer = NULL;
    size_t maxbuflen = 0;
    size_t buflen = 1;
    size_t buf_idx = 0;
    while ((!state.done || !cbor_done) && result == 0) {

        cbor_done = 0;

        if (buflen > maxbuflen) {
            buffer = (uint8_t *)udi_realloc(buffer, buflen);
            if (buffer == NULL) {
                return errno;
            }
            maxbuflen = buflen;
        }

        result = read_from(fd, buffer + buf_idx, buflen - buf_idx);
        if (result != 0) {
            snprintf(errmsg->msg, errmsg->size, "failed to read CBOR data");
            break;
        }
        buf_idx = buflen;

        struct cbor_decoder_result decode_result;
        decode_result = cbor_stream_decode(buffer,
                                           buflen,
                                           callbacks,
                                           &state);

        switch (decode_result.status) {
            case CBOR_DECODER_EBUFFER:
            case CBOR_DECODER_ERROR:
            {
                result = -1;
                snprintf(errmsg->msg, errmsg->size, "failed to decode CBOR data");
                break;
            }
            case CBOR_DECODER_NEDATA:
            {
                buflen += decode_result.required;
                break;
            }
            case CBOR_DECODER_FINISHED:
            {
                cbor_done = 1;
                buf_idx = 0;
                buflen = 1;
                break;
            }
        }
    }

    udi_free((void *)buffer);
    return result;
}

struct req_data_state {
    const struct msg_config *config;
    const struct msg_item *current_item;
    int item_count;

    int error;
    udi_errmsg *errmsg;

    void *data;
};


static inline
struct req_data_state *req_state(void *ctx) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    return (struct req_data_state *)state->ctx;
}

static
void complete_item(void *ctx) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;

    data_state->item_count++;
    if (data_state->item_count >= data_state->config->num_items) {
        state->done = 1;
    }
    data_state->current_item = NULL;
}

static
const struct msg_item *check_state(void *ctx, const char *actual_type) {

    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;

    if (data_state->error) {
        return NULL;
    }

    if (data_state->current_item == NULL) {
        state->done = 1;
        data_state->error = 1;
        snprintf(data_state->errmsg->msg, data_state->errmsg->size,
                 "received unexpected data item of type %s instead of map", actual_type);
        return NULL;
    }

    return data_state->current_item;
}

static
void set_invalid_error(void *ctx, const char *type_name) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;

    state->done = 1;
    data_state->error = 1;
    snprintf(data_state->errmsg->msg, data_state->errmsg->size,
             "received unexpected data item of type %s in map",
             type_name);
}

#define DEFINE_VALUE_CALLBACKS(N, T) \
static \
void N##_callback(void *ctx, T value) { \
    const struct msg_item *item = check_state(ctx, #N); \
    if (item != NULL) { \
        item->callbacks.N(ctx, value); \
    } \
} \
\
static \
void N##_invalid_callback(void *ctx, T value) { \
    set_invalid_error(ctx, #N); \
}

#define DEFINE_NO_VALUE_CALLBACKS(N) \
static \
void N##_callback(void *ctx) { \
    const struct msg_item *item = check_state(ctx, #N); \
    if (item != NULL) { \
        item->callbacks.N(ctx); \
    } \
} \
\
static \
void N##_invalid_callback(void *ctx) { \
    set_invalid_error(ctx, #N); \
}

#define DEFINE_STRING_CALLBACKS(N) \
static \
void N##_callback(void *ctx, cbor_data data, size_t len) { \
    const struct msg_item *item = check_state(ctx, #N); \
    if (item != NULL) { \
        item->callbacks.N(ctx, data, len); \
    } \
} \
\
static \
void N##_invalid_callback(void *ctx, cbor_data data, size_t len) { \
    set_invalid_error(ctx, #N); \
}

#define DEFINE_COLL_START_CALLBACKS(N) \
static \
void N##_callback(void *ctx, size_t len) { \
    const struct msg_item *item = check_state(ctx, #N); \
    if (item != NULL) { \
        item->callbacks.N(ctx, len); \
    } \
} \
\
static \
void N##_invalid_callback(void *ctx, size_t len) { \
    set_invalid_error(ctx, #N); \
}

DEFINE_VALUE_CALLBACKS(uint8, uint8_t)
DEFINE_VALUE_CALLBACKS(uint16, uint16_t)
DEFINE_VALUE_CALLBACKS(uint32, uint32_t)
DEFINE_VALUE_CALLBACKS(uint64, uint64_t)
DEFINE_VALUE_CALLBACKS(negint8, uint8_t)
DEFINE_VALUE_CALLBACKS(negint16, uint16_t)
DEFINE_VALUE_CALLBACKS(negint32, uint32_t)
DEFINE_VALUE_CALLBACKS(negint64, uint64_t)
DEFINE_VALUE_CALLBACKS(tag, uint64_t)
DEFINE_VALUE_CALLBACKS(float2, float)
DEFINE_VALUE_CALLBACKS(float4, float)
DEFINE_VALUE_CALLBACKS(float8, double)
DEFINE_VALUE_CALLBACKS(boolean, bool)

DEFINE_STRING_CALLBACKS(string)
DEFINE_NO_VALUE_CALLBACKS(string_start)

DEFINE_STRING_CALLBACKS(byte_string)
DEFINE_NO_VALUE_CALLBACKS(byte_string_start)

DEFINE_COLL_START_CALLBACKS(array_start)
DEFINE_NO_VALUE_CALLBACKS(indef_array_start)

DEFINE_COLL_START_CALLBACKS(map_start)
DEFINE_NO_VALUE_CALLBACKS(indef_map_start)

DEFINE_NO_VALUE_CALLBACKS(null)
DEFINE_NO_VALUE_CALLBACKS(undefined)
DEFINE_NO_VALUE_CALLBACKS(indef_break)

static
const struct cbor_callbacks invalid_callbacks = {
	.uint8 = uint8_invalid_callback,
	.uint16 = uint16_invalid_callback,
	.uint32 = uint32_invalid_callback,
	.uint64 = uint64_invalid_callback,

	.negint8 = negint8_invalid_callback,
	.negint16 = negint16_invalid_callback,
	.negint32 = negint32_invalid_callback,
	.negint64 = negint64_invalid_callback,

	.byte_string_start = byte_string_start_invalid_callback,
	.byte_string = byte_string_invalid_callback,

	.string_start = string_start_invalid_callback,
	.string = string_invalid_callback,

	.indef_array_start = indef_array_start_invalid_callback,
	.array_start = array_start_invalid_callback,

	.indef_map_start = indef_map_start_invalid_callback,
	.map_start = map_start_invalid_callback,

	.tag = tag_invalid_callback,

	.float2 = float2_invalid_callback,
	.float4 = float4_invalid_callback,
	.float8 = float8_invalid_callback,
	.undefined = undefined_invalid_callback,
	.null = null_invalid_callback,
	.boolean = boolean_invalid_callback,

	.indef_break = indef_break_invalid_callback,
};

static
const struct cbor_callbacks item_callbacks = {
	.uint8 = uint8_callback,
	.uint16 = uint16_callback,
	.uint32 = uint32_callback,
	.uint64 = uint64_callback,

	.negint8 = negint8_callback,
	.negint16 = negint16_callback,
	.negint32 = negint32_callback,
	.negint64 = negint64_callback,

	.byte_string_start = byte_string_start_callback,
	.byte_string = byte_string_callback,

	.string_start = string_start_callback,
	.string = string_callback,

	.indef_array_start = indef_array_start_callback,
	.array_start = array_start_callback,

	.indef_map_start = indef_map_start_callback,
	.map_start = map_start_callback,

	.tag = tag_callback,

	.float2 = float2_callback,
	.float4 = float4_callback,
	.float8 = float8_callback,
	.undefined = undefined_callback,
	.null = null_callback,
	.boolean = boolean_callback,

	.indef_break = indef_break_callback,
};

static
void request_data_map_start(void *ctx, size_t len) {
    struct req_data_state *data_state = req_state(ctx);

    if (data_state->error) {
        return;
    }

    if (data_state->current_item != NULL) {
        map_start_callback(ctx, len);
    }else{
        if (data_state->config->num_items != len) {
            data_state->error = 1;
            snprintf(data_state->errmsg->msg,
                     data_state->errmsg->size,
                     "Unexpected number of data items in map (expected %d, actual %lu)",
                     data_state->config->num_items,
                     len);
        }
    }
}

static
void request_data_string(void *ctx, cbor_data data, size_t len) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;

    if (data_state->error) {
        return;
    }

    if (data_state->current_item != NULL) {
        string_callback(ctx, data, len);
    }else{
        for (int i = 0; i < data_state->config->num_items; ++i) {
            struct msg_item *item = (struct msg_item *)&(data_state->config->items[i]);
            if (strncmp((const char *)data, item->key, len) == 0) {
                data_state->current_item = item;
                break;
            }
        }

        if (data_state->current_item == NULL) {
            data_state->error = 1;

            char *key = (char *)udi_calloc(1, len+1);
            if (key != NULL) {
                memcpy(key, data, len);
                key[len] = '\0';
            }else{
                key = "(no memory)";
            }

            snprintf(data_state->errmsg->msg,
                     data_state->errmsg->size,
                     "failed to locate config item for %s",
                     key);
        }
    }
}

/** Request processed successfully */
static const int REQ_SUCCESS = 0;

/** Unrecoverable failure caused by environment/OS error */
static const int REQ_ERROR = -1;

/** Failure to process request due to invalid arguments */
static const int REQ_FAILURE = -2;

static
int read_request_data(udirt_fd req_fd,
                      const struct msg_config *config,
                      void *data,
                      udi_errmsg *errmsg) {

    struct req_data_state data_state;
    memset(&data_state, 0, sizeof(data_state));
    data_state.errmsg = errmsg;
    data_state.config = config;
    data_state.data = data;

    struct cbor_callbacks callbacks = item_callbacks;
    callbacks.map_start = request_data_map_start;
    callbacks.string = request_data_string;

    int result = read_cbor_items(req_fd, &data_state, &callbacks, errmsg);
    if (result != 0) {
        return REQ_ERROR;
    }

    if (data_state.error) {
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
}

// continue request handling

static
void continue_sig_callback(void *ctx, uint32_t value) {
    continue_req *data = (continue_req *) req_state(ctx)->data;
    data->sig = value;

    complete_item(ctx);
}

static
void continue_init_config(struct msg_config *config,
                          struct msg_item *items)
{
    if (config->items == NULL) {
        items[0].key = "sig";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint32 = continue_sig_callback;

        config->num_items = 1;
        config->items = items;
    }
}

static
int continue_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[1];
    continue_init_config(&config, items);

    int result;
    continue_req data;
    memset(&data, 0, sizeof(data));

    result = read_request_data(req_fd, &config, &data, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    // TODO continue handler impl
    return REQ_FAILURE;
}

// read request handling

static
int read_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

// write request handling

static
int write_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

// state request handling

static
int state_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int init_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int breakpoint_create_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int breakpoint_install_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int breakpoint_remove_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int breakpoint_delete_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

static
int invalid_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {
    snprintf(errmsg->msg, errmsg->size, "invalid request for process");
    return REQ_ERROR;
}

typedef int (*request_handler)(udirt_fd, udirt_fd, udi_errmsg *);

static
request_handler request_handlers[] = {
    continue_handler,
    read_handler,
    write_handler,
    invalid_handler,
    invalid_handler,
    state_handler,
    init_handler,
    breakpoint_create_handler,
    breakpoint_install_handler,
    breakpoint_remove_handler,
    breakpoint_delete_handler,
    invalid_handler,
    invalid_handler,
    invalid_handler,
    invalid_handler
};

static
void request_type_callback(void *ctx, uint8_t value) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;
    udi_request_type_e *type = (udi_request_type_e *)data_state->data;

    *type = value;

    state->done = 1;
}

static
int read_request_type(udirt_fd req_fd, udi_request_type_e *type, udi_errmsg *errmsg) {

    struct cbor_callbacks callbacks = invalid_callbacks;
    callbacks.uint8 = request_type_callback;

    struct req_data_state data_state;
    memset(&data_state, 0, sizeof(data_state));
    data_state.data = type;
    data_state.errmsg = errmsg;

    int result = read_cbor_items(req_fd, &data_state, &callbacks, errmsg);
    if (result != 0) {
        return REQ_ERROR;
    }

    if (data_state.error) {
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
}

int handle_process_request(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    int result;
    do {
        udi_request_type_e type = -1;
        result = read_request_type(req_fd, &type, errmsg);
        if (result != REQ_SUCCESS) {
            break;
        }

        result = request_handlers[type](req_fd, resp_fd, errmsg);
    }while (0);

    return result;
}

int read_register_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

int write_register_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

int thr_state_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

int next_instr_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

int single_step_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}

int thr_invalid_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    snprintf(errmsg->msg, errmsg->size, "invalid request for thread");
    return REQ_ERROR;
}

typedef int (*thr_request_handler)(udirt_fd, udirt_fd, thread *, udi_errmsg *errmsg);

/*
static
thr_request_handler thr_request_handlers[] = {
    thr_invalid_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    read_register_handler,
    write_register_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    thr_invalid_handler,
    thr_state_handler,
    thr_state_handler,
    next_instr_handler,
    single_step_handler
};
*/

int handle_thread_request(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    return REQ_FAILURE;
}
