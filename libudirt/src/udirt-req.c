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
#include <inttypes.h>

#include "cbor.h"

#include "udirt.h"

// Continue handling
breakpoint *continue_bp = NULL;

// the last hit breakpoint, set with continue_bp
static uint64_t last_bp_address = 0;

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
                snprintf(errmsg->msg,
                         errmsg->size,
                         "failed to allocate memory");
                return ENOMEM;
            }
            maxbuflen = buflen;
        }

        result = read_from(fd, buffer + buf_idx, buflen - buf_idx);
        if (result != 0) {
            snprintf(errmsg->msg,
                     errmsg->size,
                     "failed to read CBOR data: %s",
                     strerror(errno));
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

static
int write_cbor_item(udirt_fd fd,
                    cbor_item_t *item,
                    const char *name,
                    udi_errmsg *errmsg)
{
    cbor_mutable_data buffer = NULL;
    size_t buffer_size = 0;
    size_t length = cbor_serialize_alloc(item, &buffer, &buffer_size);
    cbor_decref(&item);
    if (length == 0) {
        snprintf(errmsg->msg,
                 errmsg->size,
                 "failed to serialize %s",
                 name);
        return REQ_ERROR;
    }

    int result = write_to(fd, buffer, length);
    udi_free(buffer);
    if (result != 0) {
        snprintf(errmsg->msg,
                 errmsg->size,
                 "failed to write %s: %s",
                 name,
                 strerror(errno));
        return REQ_ERROR;
    }

    return REQ_SUCCESS;
}

static
int write_response(udirt_fd resp_fd,
                   udi_response_type_e resp_type,
                   udi_request_type_e req_type,
                   cbor_item_t *data,
                   udi_errmsg *errmsg)
{
    int result;

    cbor_item_t *resp_type_item = cbor_build_uint16(resp_type);
    result = write_cbor_item(resp_fd, resp_type_item, "response type", errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    cbor_item_t *req_type_item = cbor_build_uint16(req_type);
    result = write_cbor_item(resp_fd, req_type_item, "request type", errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    if (data != NULL) {
        return write_cbor_item(resp_fd, data, "response data", errmsg);
    }

    return REQ_SUCCESS;
}

static
int write_response_no_data(udirt_fd resp_fd,
                           udi_response_type_e resp_type,
                           udi_request_type_e req_type,
                           udi_errmsg *errmsg)
{
    return write_response(resp_fd, resp_type, req_type, NULL, errmsg);
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

    // special handling for a continue from a breakpoint
    if ( continue_bp != NULL ) {
        int install_result = install_breakpoint(continue_bp, errmsg);
        if ( install_result != 0 ) {
            udi_printf("failed to install breakpoint for continue at 0x%"PRIx64"\n",
                       continue_bp->address);
            if ( install_result < REQ_ERROR ) {
                install_result = REQ_ERROR;
            }
        }else{
            udi_printf("installed breakpoint at 0x%"PRIx64" for continue from breakpoint\n",
                    continue_bp->address);
        }
    }

    if (get_multithread_capable()) {
        thread *cur_thr = get_thread_list();
        while (cur_thr != NULL) {
            thread *next_thread = get_next_thread(cur_thr);
            if ( is_thread_dead(cur_thr) ) {
                if ( thread_death_handshake(cur_thr, errmsg) ) {
                    return REQ_ERROR;
                }
            }
            cur_thr = next_thread;
        }
    }

    result = write_response_no_data(resp_fd, UDI_RESP_VALID, UDI_REQ_CONTINUE, errmsg);

    if ( result == REQ_SUCCESS ) {
        post_continue_hook(data.sig);
    }

    return result;
}

// read request handling

static
void read_addr_callback(void *ctx, uint64_t value) {
    read_mem_req *data = (read_mem_req *)req_state(ctx)->data;
    data->addr = value;
}

static
void read_len_callback(void *ctx, uint32_t value) {
    read_mem_req *data = (read_mem_req *)req_state(ctx)->data;
    data->len = value;
}

static
void read_init_config(struct msg_config *config,
                      struct msg_item *items)
{
    if (config->items == NULL) {
        items[0].key = "addr";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint64 = read_addr_callback;

        items[1].key = "len";
        items[1].callbacks = invalid_callbacks;
        items[1].callbacks.uint32 = read_len_callback;

        config->num_items = 2;
        config->items = items;
    }
}

static
int read_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[2];
    read_init_config(&config, items);

    int result;
    read_mem_req data;
    memset(&data, 0, sizeof(data));

    result = read_request_data(req_fd, &config, &data, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    void *memory_read = udi_malloc(data.len);
    if ( memory_read == NULL ) {
        snprintf(errmsg->msg,
                 errmsg->size,
                 "failed to allocate memory");
        return REQ_ERROR;
    }

    // Perform the read operation
    int read_result = read_memory(memory_read, (void *)data.addr, data.len, errmsg);
    if ( read_result != 0 ) {
        udi_free(memory_read);

        const char *mem_errstr = get_mem_errstr();
        snprintf(errmsg->msg, errmsg->size, "%s", mem_errstr);
        udi_printf("failed memory read: %s\n", mem_errstr);
        return REQ_FAILURE;
    }

    cbor_item_t *mem_item = cbor_build_bytestring((cbor_data)memory_read, data.len);

    cbor_item_t *map = cbor_new_definite_map(2);

    struct cbor_pair mem_map_item;
    mem_map_item.key = cbor_move(cbor_build_string("data"));
    mem_map_item.value = cbor_move(mem_item);
    cbor_map_add(map, mem_map_item);

    result = write_response(resp_fd,
                            UDI_RESP_VALID,
                            UDI_REQ_READ_MEM,
                            map,
                            errmsg);
    udi_free(memory_read);
    return result;
}

// write request handling
static
void write_data_callback(void *ctx, cbor_data data, size_t len) {
    write_mem_req *state = (write_mem_req *)req_state(ctx)->data;

    state->data = (uint8_t *)udi_malloc(len);
    if (state->data != NULL) {
        memcpy((void *)state->data, data, len);
        state->len = len;
    }
}

static
void write_addr_callback(void *ctx, uint64_t value) {
    write_mem_req *state = (write_mem_req *)req_state(ctx)->data;
    state->addr = value;
}

static
void write_config_init(struct msg_config *config,
                       struct msg_item *items)
{
    if (config->items == NULL) {
        items[0].key = "addr";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint64 = write_addr_callback;

        items[1].key = "data";
        items[1].callbacks = invalid_callbacks;
        items[1].callbacks.byte_string = write_data_callback;

        config->num_items = 2;
        config->items = items;
    }
}

static
int write_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[2];
    write_config_init(&config, items);

    int result;
    write_mem_req req;
    memset(&req, 0, sizeof(req));

    result = read_request_data(req_fd, &config, &req, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    // Perform the write operation
    int write_result = write_memory((void *)(unsigned long)req.addr,
                                    req.data,
                                    req.len,
                                    errmsg);
    udi_free((void *)req.data);
    if ( write_result != 0 ) {
        const char *mem_errstr = get_mem_errstr();
        snprintf(errmsg->msg, errmsg->size, "%s", mem_errstr);
        udi_printf("failed write request: %s\n", mem_errstr);
        return REQ_FAILURE;
    }

    return write_response_no_data(resp_fd, UDI_RESP_VALID, UDI_REQ_WRITE_MEM, errmsg);
}

// state request handling

static
int state_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    int num_threads = get_num_threads();

    cbor_item_t *array = cbor_new_definite_array(num_threads);

    thread *thr = get_thread_list();
    while (thr != NULL) {
        cbor_item_t *state_map = cbor_new_definite_map(2);

        struct cbor_pair tid_pair;
        tid_pair.key = cbor_move(cbor_build_string("tid"));
        tid_pair.value = cbor_move(cbor_build_uint64(get_thread_id(thr)));
        cbor_map_add(state_map, tid_pair);

        struct cbor_pair state_pair;
        state_pair.key = cbor_move(cbor_build_string("state"));
        state_pair.value = cbor_move(cbor_build_uint16(get_thread_state(thr)));
        cbor_map_add(state_map, state_pair);

        cbor_array_push(array, cbor_move(state_map));

        thr = get_next_thread(thr);
    }

    cbor_item_t *map = cbor_new_definite_map(1);

    struct cbor_pair states_pair;
    states_pair.key = cbor_move(cbor_build_string("states"));
    states_pair.value = cbor_move(array);
    cbor_map_add(map, states_pair);

    return write_response(resp_fd, UDI_RESP_VALID, UDI_REQ_STATE, map, errmsg);
}

// init request handling

static
int init_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    cbor_item_t *map = cbor_new_definite_map(4);

    struct cbor_pair v_pair;
    v_pair.key = cbor_move(cbor_build_string("v"));
    v_pair.value = cbor_move(cbor_build_uint32(get_protocol_version()));
    cbor_map_add(map, v_pair);

    struct cbor_pair arch_pair;
    arch_pair.key = cbor_move(cbor_build_string("arch"));
    arch_pair.value = cbor_move(cbor_build_uint16(get_architecture()));
    cbor_map_add(map, arch_pair);

    struct cbor_pair mt_pair;
    mt_pair.key = cbor_move(cbor_build_string("mt"));
    mt_pair.value = cbor_move(cbor_build_bool(get_multithread_capable()));
    cbor_map_add(map, mt_pair);

    struct cbor_pair tid_pair;
    tid_pair.key = cbor_move(cbor_build_string("tid"));
    tid_pair.value = cbor_move(cbor_build_uint64(get_thread_id(get_current_thread())));
    cbor_map_add(map, tid_pair);

    return write_response(req_fd, UDI_RESP_VALID, UDI_REQ_INIT, map, errmsg);
}

// breakpoint request handling

static
void breakpoint_addr_callback(void *ctx, uint64_t value) {
    brkpt_req *req = (brkpt_req *)req_state(ctx)->data;
    req->addr = value;
}

static
void breakpoint_init_config(struct msg_config *config,
                            struct msg_item *items) {

    if (config->items == NULL) {
        items[0].key = "addr";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint64 = breakpoint_addr_callback;

        config->num_items = 1;
        config->items = items;
    }
}

static
int read_breakpoint_addr(udirt_fd req_fd, uint64_t *addr, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[1];

    brkpt_req req;
    memset(&req, 0, sizeof(req));

    int result = read_request_data(req_fd, &config, &req, errmsg);
    if (result == REQ_SUCCESS) {
        *addr = req.addr;
    }
    return result;
}

static
int breakpoint_create_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    uint64_t addr;

    int result = read_breakpoint_addr(req_fd, &addr, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    breakpoint *bp = find_breakpoint(addr);

    // A breakpoint already exists
    if ( bp != NULL ) {
        snprintf(errmsg->msg,
                 errmsg->size,
                 "breakpoint already exists at 0x%"PRIx64,
                 addr);
        udi_printf("attempt to create duplicate breakpoint at 0x%"PRIx64"\n", addr);
        return REQ_FAILURE;
    }

    bp = create_breakpoint(addr);

    if ( bp == NULL ) {
        snprintf(errmsg->msg, errmsg->size, "failed to create breakpoint at 0x%"PRIx64, addr);
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    return write_response_no_data(resp_fd, UDI_RESP_VALID, UDI_REQ_CREATE_BREAKPOINT, errmsg);
}

static
int read_breakpoint(udirt_fd req_fd, breakpoint **bp, udi_errmsg *errmsg) {

    uint64_t addr;

    int result = read_breakpoint_addr(req_fd, &addr, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    *bp = find_breakpoint(addr);
    if ( bp == NULL ) {
        snprintf(errmsg->msg, errmsg->size, "no breakpoint exists at 0x%"PRIx64, addr);
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
}

static
int breakpoint_install_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    breakpoint *bp = NULL;
    int result = read_breakpoint(req_fd, &bp, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    result = install_breakpoint(bp, errmsg);
    if (result != 0) {
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
}

static
int breakpoint_remove_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    breakpoint *bp = NULL;
    int result = read_breakpoint(req_fd, &bp, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    result = remove_breakpoint(bp, errmsg);
    if (result != 0) {
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
}

static
int breakpoint_delete_handler(udirt_fd req_fd, udirt_fd resp_fd, udi_errmsg *errmsg) {

    breakpoint *bp = NULL;
    int result = read_breakpoint(req_fd, &bp, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    result = delete_breakpoint(bp, errmsg);
    if (result != 0) {
        return REQ_FAILURE;
    }

    return REQ_SUCCESS;
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
void request_type_callback(void *ctx, uint16_t value) {
    struct cbor_read_state *state = (struct cbor_read_state *)ctx;
    struct req_data_state *data_state = (struct req_data_state *)state->ctx;
    udi_request_type_e *type = (udi_request_type_e *)data_state->data;

    *type = value;

    state->done = 1;
}

static
int read_request_type(udirt_fd req_fd, udi_request_type_e *type, udi_errmsg *errmsg) {

    struct cbor_callbacks callbacks = invalid_callbacks;
    callbacks.uint16 = request_type_callback;

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

static
void read_reg_callback(void *ctx, uint16_t value) {
    read_reg_req *req = (read_reg_req *)req_state(ctx)->data;
    req->reg = value;
}

static
void read_reg_init_config(struct msg_config *config,
                          struct msg_item *items)
{
    if (config->items == NULL) {
        items[0].key = "reg";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint16 = read_reg_callback;

        config->items = items;
        config->num_items = 1;
    }
}

static
int read_register_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[1];
    read_reg_init_config(&config, items);

    read_reg_req req;
    memset(&req, 0, sizeof(req));

    int result = read_request_data(req_fd, &config, &req, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    if (!is_thread_context_valid(thr)) {
        snprintf(errmsg->msg, errmsg->size, "%s", "register context is unavailable");
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    uint64_t value;
    result = get_register(get_architecture(),
                          req.reg,
                          errmsg,
                          &value,
                          get_thread_context(thr));
    if ( result != 0 ) {
        return REQ_FAILURE;
    }

    cbor_item_t *map = cbor_new_definite_map(1);

    struct cbor_pair value_pair;
    value_pair.key = cbor_move(cbor_build_string("value"));
    value_pair.value = cbor_move(cbor_build_uint64(value));
    cbor_map_add(map, value_pair);

    return write_response(resp_fd, UDI_RESP_VALID, UDI_REQ_READ_REGISTER, map, errmsg);
}

static
void write_reg_callback(void *ctx, uint16_t value) {
    write_reg_req *req = (write_reg_req *)req_state(ctx)->data;
    req->reg = value;
}

static
void write_reg_value_callback(void *ctx, uint64_t value) {
    write_reg_req *req = (write_reg_req *)req_state(ctx)->data;
    req->value = value;
}

static
void write_reg_init_config(struct msg_config *config,
                           struct msg_item *items) {

    if (config->items == NULL) {
        items[0].key = "reg";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.uint16 = write_reg_callback;

        items[1].key = "value";
        items[1].callbacks = invalid_callbacks;
        items[1].callbacks.uint64 = write_reg_value_callback;

        config->items = items;
        config->num_items = 2;
    }
}

static
int write_register_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[2];
    write_reg_init_config(&config, items);

    write_reg_req req;
    memset(&req, 0, sizeof(req));

    int result = read_request_data(req_fd, &config, &req, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    if (!is_thread_context_valid(thr)) {
        snprintf(errmsg->msg, errmsg->size, "%s", "register context is unavailable");
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    result = set_register(get_architecture(),
                          req.reg,
                          errmsg,
                          req.value,
                          get_thread_context(thr));
    if (result != 0) {
        return REQ_FAILURE;
    }

    return write_response_no_data(resp_fd, UDI_RESP_VALID, UDI_REQ_WRITE_REGISTER, errmsg);
}

static
int thr_state_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    cbor_item_t *map = cbor_new_definite_map(2);

    struct cbor_pair tid_pair;
    tid_pair.key = cbor_move(cbor_build_string("tid"));
    tid_pair.value = cbor_move(cbor_build_uint64(get_thread_id(thr)));
    cbor_map_add(map, tid_pair);

    struct cbor_pair state_pair;
    state_pair.key = cbor_move(cbor_build_string("state"));
    state_pair.value = cbor_move(cbor_build_uint16(get_thread_state(thr)));
    cbor_map_add(map, state_pair);

    return write_response(resp_fd, UDI_RESP_VALID, UDI_REQ_STATE, map, errmsg);
}

static
int next_instr_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    if (!is_thread_context_valid(thr)) {
        snprintf(errmsg->msg, errmsg->size, "%s", "register context unavailable");
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    const void *context = get_thread_context(thr);

    uint64_t pc = get_pc(context);
    uint64_t address = get_ctf_successor(pc, errmsg, context);
    if (address == 0) {
        snprintf(errmsg->msg, errmsg->size, 
                "failed to determine successor instruction from 0x%"PRIx64, pc);
        udi_printf("%s\n", errmsg->msg);
        return REQ_FAILURE;
    }

    cbor_item_t *map = cbor_new_definite_map(1);

    struct cbor_pair addr_pair;
    addr_pair.key = cbor_move(cbor_build_string("addr"));
    addr_pair.value = cbor_move(cbor_build_uint64(address));

    return write_response(resp_fd, UDI_RESP_VALID, UDI_REQ_NEXT_INSTRUCTION, map, errmsg);
}

static
void single_step_callback(void *ctx, bool value) {
    single_step_req *req = (single_step_req *)req_state(ctx)->data;
    req->setting = value;
}

static
void single_step_init_config(struct msg_config *config,
                             struct msg_item *items)
{
    if (config->items == NULL) {
        items[0].key = "value";
        items[0].callbacks = invalid_callbacks;
        items[0].callbacks.boolean = single_step_callback;

        config->items = items;
        config->num_items = 1;
    }
}

static
int single_step_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    static struct msg_config config;
    static struct msg_item items[1];
    single_step_init_config(&config, items);

    single_step_req req;
    memset(&req, 0, sizeof(req));

    int result = read_request_data(req_fd, &config, &req, errmsg);
    if (result != REQ_SUCCESS) {
        return result;
    }

    bool prev_setting = get_single_step(thr);
    set_single_step(thr, req.setting);

    cbor_item_t *map = cbor_new_definite_map(1);

    struct cbor_pair value_pair;
    value_pair.key = cbor_move(cbor_build_string("value"));
    value_pair.value = cbor_move(cbor_build_bool(prev_setting));
    cbor_map_add(map, value_pair);

    return write_response(resp_fd, UDI_RESP_VALID, UDI_REQ_SINGLE_STEP, map, errmsg);
}

int thr_invalid_handler(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {
    snprintf(errmsg->msg, errmsg->size, "invalid request for thread");
    return REQ_ERROR;
}

typedef int (*thr_request_handler)(udirt_fd, udirt_fd, thread *, udi_errmsg *errmsg);

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

int handle_thread_request(udirt_fd req_fd, udirt_fd resp_fd, thread *thr, udi_errmsg *errmsg) {

    int result;
    do {
        udi_request_type_e type = -1;
        result = read_request_type(req_fd, &type, errmsg);
        if (result != REQ_SUCCESS) {
            break;
        }

        result = thr_request_handlers[type](req_fd, resp_fd, thr, errmsg);
    }while (0);

    return result;
}

int write_error_response(udirt_fd resp_fd, udi_request_type_e req_type, udi_errmsg *errmsg) {
    cbor_item_t *map = cbor_new_definite_map(2);

    struct cbor_pair msg_pair;
    msg_pair.key = cbor_move(cbor_build_string("msg"));
    msg_pair.value = cbor_move(cbor_build_string(errmsg->msg));
    cbor_map_add(map, msg_pair);

    return write_response(resp_fd, UDI_RESP_ERROR, req_type, map, errmsg);
}

static
int write_event(udirt_fd fd,
                udi_event_type_e event_type,
                uint64_t tid,
                cbor_item_t *data,
                udi_errmsg *errmsg)
{
    // TODO
}

int decode_breakpoint(thread *thr,
                      breakpoint *bp,
                      void *context,
                      int **wait_for_request,
                      udi_errmsg *errmsg)
{
    rewind_pc(context);
    if (thr != NULL) {
        // make sure a read of the pc at a breakpoint returns the expected value
        rewind_pc(get_thread_context(thr));
    }

    // Handle single step breakpoints
    if (thr != NULL && get_single_step_breakpoint(thr) == bp) {
        udi_printf("single step breakpoint at 0x%"PRIx64"\n", bp->address);

        int delete_result = delete_breakpoint(bp, errmsg);
        if (delete_result != 0) {
            snprintf(errmsg->msg,
                     errmsg->size,
                     "failed to delete breakpoint at 0x%"PRIx64,
                     bp->address);
            return REQ_ERROR;
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

