/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "ibm_logs.h"
#include "ibm_auth.h"

/* Field mapping structure for efficiency */
struct field_mapping {
    const char *name;
    size_t name_len;
    const char *mapped_name;
    size_t mapped_name_len;
};

static const struct field_mapping FIELD_MAPPINGS[] = {
    {"level", 5, "severity", 8},
    {"severity", 8, "severity", 8},
    {"computerName", 12, "computerName", 12},
    {"category", 8, "category", 8},
    {"className", 9, "className", 9},
    {"methodName", 10, "methodName", 10},
    {"threadId", 8, "threadId", 8}
};

#define FIELD_MAPPINGS_COUNT (sizeof(FIELD_MAPPINGS) / sizeof(FIELD_MAPPINGS[0]))

int flb_ibm_logs_conf_destroy(struct flb_ibm_logs *ctx)
{
    if (!ctx) {
        return -1;
    }

    /* Destroy string fields */
    if (ctx->ibm_logs_host) {
        flb_sds_destroy(ctx->ibm_logs_host);
    }

    if (ctx->ibm_logs_path) {
        flb_sds_destroy(ctx->ibm_logs_path);
    }

    if (ctx->application_name) {
        flb_sds_destroy(ctx->application_name);
    }

    if (ctx->subsystem_name) {
        flb_sds_destroy(ctx->subsystem_name);
    }

    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }

    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->auth_mutex);

    flb_free(ctx);

    return 0;
}

static int cb_ibm_logs_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_ibm_logs *ctx;
    struct flb_upstream *upstream;

    flb_plg_debug(ins, "initializing IBM Cloud Logs output plugin");

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_ibm_logs));
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }
    ctx->ins = ins;

    /* Initialize mutex */
    ret = pthread_mutex_init(&ctx->auth_mutex, NULL);
    if (ret != 0) {
        flb_plg_error(ins, "failed to initialize auth mutex: %s", strerror(ret));
        flb_free(ctx);
        return -1;
    }

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        goto error;
    }

    /* Validate port */
    if (ctx->ibm_logs_port <= 0 || ctx->ibm_logs_port > 65535) {
        flb_plg_error(ctx->ins, "invalid port number: %d", ctx->ibm_logs_port);
        goto error;
    }

    /* Validate host */
    if (!ctx->ibm_logs_host || strlen(ctx->ibm_logs_host) == 0) {
        flb_plg_error(ctx->ins, "host cannot be empty");
        goto error;
    }

    /* Validate authentication mode */
    if (strcmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) != 0 &&
        strcmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) != 0) {
        flb_plg_error(ctx->ins, "invalid authentication mode: %s",
                      ctx->ibm_iam_authentication_mode);
        goto error;
    }

    /* Set default path if not provided */
    if (!ctx->ibm_logs_path) {
        ctx->ibm_logs_path = flb_sds_create(FLB_IBM_LOGS_PATH);
        if (!ctx->ibm_logs_path) {
            flb_plg_error(ctx->ins, "failed to allocate default ibm logs path");
            goto error;
        }
    }

    /* Create upstream connection context */
    upstream = flb_upstream_create(config,
                                   ctx->ibm_logs_host,
                                   ctx->ibm_logs_port,
                                   FLB_IO_TLS, ins->tls);
    
    if (!upstream) {
        flb_plg_error(ins, "upstream creation failed");
        goto error;
    }

    ctx->upstream = upstream;
    flb_output_upstream_set(ctx->upstream, ins);

    /* Pre-allocate CR token buffer */
    ctx->cr_token_buffer = flb_calloc(1, MAX_CR_TOKEN_SIZE);
    if (!ctx->cr_token_buffer) {
        flb_plg_error(ins, "failed to allocate CR token buffer");
        goto error;
    }

    /* Initialize authentication */
    ret = ibm_auth_init(ctx);
    if (ret != 0) {
        flb_plg_error(ins, "failed to initialize authentication");
        goto error;
    }

    /* Get initial token */
    ret = ibm_auth_get_token(ctx, config);
    if (ret != 0) {
        flb_plg_error(ins, "failed to obtain initial token");
        goto error;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    /* Register debugging callbacks */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ctx->ins, "plugin configured port=%d host=%s", 
                 ctx->ibm_logs_port, ctx->ibm_logs_host);

    flb_plg_info(ins, "IBM Cloud Logs plugin initialized successfully");

    return 0;

error:
    flb_ibm_logs_conf_destroy(ctx);
    return -1;
}

/* Secure namespace extraction from Kubernetes log path */
static char* parse_namespace_from_path(struct flb_ibm_logs *ctx, 
                                       const char *file_path, 
                                       int file_path_len)
{
    const char *namespace_start;
    const char *namespace_end;
    int namespace_len;
    char *result;
    
    /* Validate input */
    if (!file_path || file_path_len <= K8S_LOG_PATH_PREFIX_LEN) {
        return NULL;
    }
    
    /* Check prefix */
    if (memcmp(file_path, K8S_LOG_PATH_PREFIX, K8S_LOG_PATH_PREFIX_LEN) != 0) {
        return NULL;
    }
    
    /* Find first underscore (end of pod name) */
    namespace_start = memchr(file_path + K8S_LOG_PATH_PREFIX_LEN, '_', 
                             file_path_len - K8S_LOG_PATH_PREFIX_LEN);
    if (!namespace_start) {
        return NULL;
    }
    namespace_start++;
    
    /* Find second underscore (end of namespace) */
    namespace_end = memchr(namespace_start, '_', 
                          file_path_len - (namespace_start - file_path));
    if (!namespace_end) {
        return NULL;
    }
    
    namespace_len = namespace_end - namespace_start;
    if (namespace_len <= 0 || namespace_len > K8S_NAMESPACE_MAX_LEN) {
        return NULL;
    }
    
    /* Allocate and copy namespace */
    result = flb_sds_create_len(namespace_start, namespace_len);
    if (!result) {
        flb_plg_error(ctx->ins, "Failed to allocate namespace from path");
    }
    
    return result;
}

/* Secure container name extraction from Kubernetes log path */
static char* parse_container_from_path(struct flb_ibm_logs *ctx,
                                       const char *file_path,
                                       int file_path_len)
{
    const char *container_start;
    const char *container_end;
    char *last_hyphen;
    int container_len;
    char *result;
    int underscore_count = 0;
    int i;
    
    /* Validate input */
    if (!file_path || file_path_len <= (K8S_LOG_PATH_PREFIX_LEN + K8S_LOG_SUFFIX_LEN)) {
        return NULL;
    }
    
    /* Check prefix and suffix */
    if (memcmp(file_path, K8S_LOG_PATH_PREFIX, K8S_LOG_PATH_PREFIX_LEN) != 0) {
        return NULL;
    }
    
    if (memcmp(file_path + file_path_len - K8S_LOG_SUFFIX_LEN, 
               K8S_LOG_SUFFIX, K8S_LOG_SUFFIX_LEN) != 0) {
        return NULL;
    }
    
    /* Find the second underscore */
    container_start = (char *)(file_path + K8S_LOG_PATH_PREFIX_LEN);
    for (i = 0; i < file_path_len - K8S_LOG_PATH_PREFIX_LEN; i++) {
        if (container_start[i] == '_') {
            underscore_count++;
            if (underscore_count == 2) {
                container_start = &container_start[i + 1];
                break;
            }
        }
    }
    
    if (underscore_count != 2) {
        return NULL;
    }
    
    /* Find last hyphen before .log */
    last_hyphen = NULL;
    for (i = file_path_len - K8S_LOG_SUFFIX_LEN - 1; 
         i >= (container_start - file_path); i--) {
        if (file_path[i] == '-') {
            last_hyphen = (char *)&file_path[i];
            break;
        }
    }
    
    if (!last_hyphen || last_hyphen <= container_start) {
        return NULL;
    }
    
    container_end = last_hyphen;
    container_len = container_end - container_start;
    
    /* Validate container name length */
    if (container_len <= 0 || container_len > K8S_CONTAINER_MAX_LEN) {
        return NULL;
    }
    
    /* Check if it's just a container ID (64 hex chars) */
    if (container_len == K8S_CONTAINER_ID_LEN) {
        int is_hex = 1;
        for (i = 0; i < container_len; i++) {
            char c = container_start[i];
            if (!((c >= '0' && c <= '9') || 
                  (c >= 'a' && c <= 'f') || 
                  (c >= 'A' && c <= 'F'))) {
                is_hex = 0;
                break;
            }
        }
        if (is_hex) {
            flb_plg_debug(ctx->ins, 
                         "Path appears to contain only container ID without name");
            return NULL;
        }
    }
    
    /* Allocate and copy container name */
    result = flb_sds_create_len(container_start, container_len);
    if (!result) {
        flb_plg_error(ctx->ins, "Failed to allocate container name from path");
    } else {
        flb_plg_debug(ctx->ins, 
                     "Parsed container name from path: '%s' (length: %d)", 
                     result, container_len);
    }
    
    return result;
}

/* Extract application name with proper validation */
static void extract_application_name(struct flb_ibm_logs *ctx,
                                    msgpack_object *kubernetes_map,
                                    const char *file_path,
                                    int file_path_len,
                                    flb_sds_t *app_name)
{
    int j;
    msgpack_object k;
    msgpack_object v;
    char *parsed_namespace = NULL;
    
    if (!app_name) {
        flb_plg_error(ctx->ins, "Invalid app_name pointer");
        return;
    }
    
    *app_name = NULL;
    
    /* Try Kubernetes metadata namespace_name */
    if (kubernetes_map && kubernetes_map->type == MSGPACK_OBJECT_MAP) {
        for (j = 0; j < kubernetes_map->via.map.size; j++) {
            k = kubernetes_map->via.map.ptr[j].key;
            v = kubernetes_map->via.map.ptr[j].val;
            
            if (k.type == MSGPACK_OBJECT_STR && 
                k.via.str.size == FIELD_NAMESPACE_NAME_LEN &&
                memcmp(k.via.str.ptr, FIELD_NAMESPACE_NAME, FIELD_NAMESPACE_NAME_LEN) == 0) {
                
                if (v.type == MSGPACK_OBJECT_STR && v.via.str.size > 0) {
                    *app_name = flb_sds_create_len(v.via.str.ptr, v.via.str.size);
                    if (*app_name) {
                        flb_plg_debug(ctx->ins, 
                                     "Application name set from namespace_name: %s", 
                                     *app_name);
                        return;
                    }
                    flb_plg_error(ctx->ins, 
                                 "Failed to allocate application name from namespace_name");
                }
                break;
            }
        }
    }
    
    /* Try parsing from file path */
    if (file_path && file_path_len > 0) {
        parsed_namespace = parse_namespace_from_path(ctx, file_path, file_path_len);
        if (parsed_namespace) {
            *app_name = parsed_namespace;
            flb_plg_debug(ctx->ins, 
                         "Application name parsed from file path: %s", 
                         *app_name);
            return;
        }
    }
    
    /* Fall back to default */
    *app_name = flb_sds_create(DEFAULT_APP_NAME);
    if (!*app_name) {
        flb_plg_error(ctx->ins, "Critical: Failed to allocate default application name");
    } else {
        flb_plg_debug(ctx->ins, "Using default application name: %s", *app_name);
    }
}

/* Extract subsystem name with proper validation */
static void extract_subsystem_name(struct flb_ibm_logs *ctx,
                                  msgpack_object *kubernetes_map,
                                  const char *file_path,
                                  int file_path_len,
                                  flb_sds_t *subsystem_name)
{
    int j;
    msgpack_object k;
    msgpack_object v;
    char *parsed_container = NULL;
    
    if (!subsystem_name) {
        flb_plg_error(ctx->ins, "Invalid subsystem_name pointer");
        return;
    }
    
    *subsystem_name = NULL;
    
    /* Try Kubernetes metadata container_name */
    if (kubernetes_map && kubernetes_map->type == MSGPACK_OBJECT_MAP) {
        for (j = 0; j < kubernetes_map->via.map.size; j++) {
            k = kubernetes_map->via.map.ptr[j].key;
            v = kubernetes_map->via.map.ptr[j].val;
            
            if (k.type == MSGPACK_OBJECT_STR && 
                k.via.str.size == FIELD_CONTAINER_NAME_LEN &&
                memcmp(k.via.str.ptr, FIELD_CONTAINER_NAME, FIELD_CONTAINER_NAME_LEN) == 0) {
                
                if (v.type == MSGPACK_OBJECT_STR && v.via.str.size > 0) {
                    *subsystem_name = flb_sds_create_len(v.via.str.ptr, v.via.str.size);
                    if (*subsystem_name) {
                        flb_plg_debug(ctx->ins, 
                                     "Subsystem name set from container_name: %s", 
                                     *subsystem_name);
                        return;
                    }
                    flb_plg_error(ctx->ins, 
                                 "Failed to allocate subsystem name from container_name");
                }
                break;
            }
        }
    }
    
    /* Try parsing from file path */
    if (file_path && file_path_len > 0) {
        parsed_container = parse_container_from_path(ctx, file_path, file_path_len);
        if (parsed_container) {
            *subsystem_name = parsed_container;
            flb_plg_debug(ctx->ins, 
                         "Subsystem name parsed from file path: %s", 
                         *subsystem_name);
            return;
        }
    }
    
    /* Fall back to default */
    *subsystem_name = flb_sds_create(DEFAULT_SUBSYSTEM_NAME);
    if (!*subsystem_name) {
        flb_plg_error(ctx->ins, "Critical: Failed to allocate default subsystem name");
    } else {
        flb_plg_debug(ctx->ins, "Using default subsystem name: %s", *subsystem_name);
    }
}

/* Count logs with threshold checking */
static int count_logs_with_threshold(size_t last_offset, size_t threshold,
                                    struct flb_log_event_decoder *log_decoder,
                                    struct flb_ibm_logs *ctx)
{
    int ret;
    int array_size = 0;
    size_t off = 0;
    struct flb_log_event log_event;

    if (last_offset != 0) {
        log_decoder->offset = last_offset;
    }

    while ((ret = flb_log_event_decoder_next(
                    log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder->offset;
        array_size++;

        if (off >= (threshold + last_offset)) {
            flb_plg_debug(ctx->ins,
                          "the offset %zu exceeded the threshold %zu. "
                          "Splitting payload at %d record.",
                          off, threshold, array_size);
            break;
        }
    }

    return array_size;
}

/* Compose payload with enhanced efficiency */
static flb_sds_t ibm_cloud_logs_compose_payload(struct flb_ibm_logs *ctx,
                                                const void *data, size_t bytes,
                                                const char *tag, int tag_len,
                                                size_t last_offset,
                                                size_t threshold, size_t *out_offset,
                                                struct flb_log_event_decoder *log_decoder)
{
    int ret;
    int record_count = 0;
    size_t off = 0;
    size_t last_off = 0;
    size_t m;

    flb_sds_t json;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    flb_sds_t app_name_to_use = NULL;
    flb_sds_t subsystem_name_to_use = NULL;
    int should_free_app_name = 0;
    int should_free_subsystem_name = 0;
    
    struct flb_log_event log_event;

    /* Count records that fit within threshold */
    record_count = count_logs_with_threshold(last_offset, threshold, log_decoder, ctx);

    /* Reset the decoder */
    flb_log_event_decoder_reset(log_decoder, (char *) data, bytes);

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Create array of log objects */
    msgpack_pack_array(&mp_pck, record_count);

    /* Adjust decoder offset */
    if (last_offset != 0) {
        log_decoder->offset = last_offset;
    }

    flb_plg_debug(ctx->ins, "tag=%s", tag);

    while ((ret = flb_log_event_decoder_next(
                    log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder->offset;
        last_off = off;

        int i;
        int fields_count = 3; /* minimum: applicationName, subsystemName, text */
        msgpack_object k, v;

        msgpack_object *kubernetes_map = NULL;
        const char *file_path = NULL;
        int file_path_len = 0;
        
        /* Reset per-iteration variables */
        app_name_to_use = NULL;
        subsystem_name_to_use = NULL;
        should_free_app_name = 0;
        should_free_subsystem_name = 0;
        
        /* Count and identify fields in first pass */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            k = log_event.body->via.map.ptr[i].key;
            v = log_event.body->via.map.ptr[i].val;

            /* Check for kubernetes metadata */
            if (k.type == MSGPACK_OBJECT_STR &&
                k.via.str.size == FIELD_KUBERNETES_LEN && 
                memcmp(k.via.str.ptr, FIELD_KUBERNETES, FIELD_KUBERNETES_LEN) == 0) {
                if (v.type == MSGPACK_OBJECT_MAP) {
                    kubernetes_map = &v;
                }
            }
            /* Check for file field */
            else if (k.type == MSGPACK_OBJECT_STR &&
                     k.via.str.size == FIELD_FILE_LEN && 
                     memcmp(k.via.str.ptr, FIELD_FILE, FIELD_FILE_LEN) == 0) {
                if (v.type == MSGPACK_OBJECT_STR) {
                    file_path = v.via.str.ptr;
                    file_path_len = v.via.str.size;
                }
            }

            /* Check for mapped fields */
            if (k.type == MSGPACK_OBJECT_STR) {
                for (m = 0; m < FIELD_MAPPINGS_COUNT; m++) {
                    if (k.via.str.size == FIELD_MAPPINGS[m].name_len &&
                        memcmp(k.via.str.ptr, FIELD_MAPPINGS[m].name, 
                               FIELD_MAPPINGS[m].name_len) == 0) {
                        fields_count++;
                        break;
                    }
                }
            }
        }

        /* Add timestamp field */
        fields_count++;
        
        /* Create log object map */
        msgpack_pack_map(&mp_pck, fields_count);

        /* Required field: applicationName */
        msgpack_pack_str(&mp_pck, 15);
        msgpack_pack_str_body(&mp_pck, "applicationName", 15);

        if (ctx->application_name) {
            app_name_to_use = ctx->application_name;
        } else {
            extract_application_name(ctx, kubernetes_map, file_path, file_path_len,
                                    &app_name_to_use);
            should_free_app_name = 1;
            
            if (!app_name_to_use) {
                flb_plg_error(ctx->ins, "Failed to extract application name");
                goto error;
            }
        }
        
        msgpack_pack_str(&mp_pck, flb_sds_len(app_name_to_use));
        msgpack_pack_str_body(&mp_pck, app_name_to_use, flb_sds_len(app_name_to_use));
        
        /* Required field: subsystemName */
        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "subsystemName", 13);

        if (ctx->subsystem_name) {
            subsystem_name_to_use = ctx->subsystem_name;
        } else {
            extract_subsystem_name(ctx, kubernetes_map, file_path, file_path_len,
                                  &subsystem_name_to_use);
            should_free_subsystem_name = 1;
            
            if (!subsystem_name_to_use) {
                flb_plg_error(ctx->ins, "Failed to extract subsystem name");
                if (should_free_app_name && app_name_to_use) {
                    flb_sds_destroy(app_name_to_use);
                }
                goto error;
            }
        }
        
        msgpack_pack_str(&mp_pck, flb_sds_len(subsystem_name_to_use));
        msgpack_pack_str_body(&mp_pck, subsystem_name_to_use, flb_sds_len(subsystem_name_to_use));

        /* Required field: text */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "text", 4);
        msgpack_pack_object(&mp_pck, *log_event.body);

        /* Required field: timestamp */
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);
        msgpack_pack_uint64(&mp_pck, (uint64_t)(flb_time_to_double(&log_event.timestamp) * 1000));

        /* Optional mapped fields */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            k = log_event.body->via.map.ptr[i].key;
            v = log_event.body->via.map.ptr[i].val;

            if (k.type == MSGPACK_OBJECT_STR) {
                for (m = 0; m < FIELD_MAPPINGS_COUNT; m++) {
                    if (k.via.str.size == FIELD_MAPPINGS[m].name_len &&
                        memcmp(k.via.str.ptr, FIELD_MAPPINGS[m].name, 
                               FIELD_MAPPINGS[m].name_len) == 0) {
                        msgpack_pack_str(&mp_pck, FIELD_MAPPINGS[m].mapped_name_len);
                        msgpack_pack_str_body(&mp_pck, FIELD_MAPPINGS[m].mapped_name, 
                                            FIELD_MAPPINGS[m].mapped_name_len);
                        msgpack_pack_object(&mp_pck, v);
                        break;
                    }
                }
            }
        }
        
        /* Free dynamically allocated names if needed */
        if (should_free_app_name && app_name_to_use) {
            flb_sds_destroy(app_name_to_use);
            app_name_to_use = NULL;
        }
        if (should_free_subsystem_name && subsystem_name_to_use) {
            flb_sds_destroy(subsystem_name_to_use);
            subsystem_name_to_use = NULL;
        }

        if (off >= (threshold + last_offset)) {
            flb_plg_debug(ctx->ins,
                          "the offset %zu exceeded the threshold %zu. "
                          "Splitting payload at this point",
                          off, threshold);
            break;
        }
    }

    *out_offset = last_off;

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    if (!json) {
        flb_plg_error(ctx->ins, "Failed to convert msgpack to JSON");
        goto error;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;

error:
    msgpack_sbuffer_destroy(&mp_sbuf);
    
    /* Clean up any remaining allocations */
    if (should_free_app_name && app_name_to_use) {
        flb_sds_destroy(app_name_to_use);
    }
    if (should_free_subsystem_name && subsystem_name_to_use) {
        flb_sds_destroy(subsystem_name_to_use);
    }

    return NULL;
}

/* Enhanced flush callback */
static void cb_ibm_logs_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int result;
    int ret_code = FLB_RETRY;
    size_t payload_len;
    flb_sds_t payload = NULL;
    size_t b_sent;
    struct flb_ibm_logs *ctx = out_context;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *http_client = NULL;
    struct flb_log_event_decoder log_decoder;

    /* Calculate thresholds in bytes */
    const size_t two_mebibytes = (size_t)(HTTP_PAYLOAD_MAX_MB * 1024 * 1024);
    size_t threshold = (size_t)(HTTP_PAYLOAD_THRESHOLD_MB * 1024 * 1024);
    size_t offset = 0;
    size_t out_offset = 0;
    int need_loop = FLB_TRUE;
    int retries = 0;

    flb_plg_debug(ctx->ins, "flush: processing %zu bytes of data", event_chunk->size);

    /* Refresh token if needed */
    result = ibm_auth_refresh_if_needed(ctx, config);
    if (result != 0) {
        flb_plg_error(ctx->ins, "failed to refresh authentication token");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Prepare log decoder */
    result = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, 
                                        event_chunk->size);
    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error : %d", result);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while (need_loop) {
    retry:
        if (retries > 0) {
            /* Reduce threshold based on retry count */
            threshold = (size_t)((HTTP_RETRY_LIMIT - retries) * 
                                 HTTP_RETRY_REDUCTION_FACTOR * two_mebibytes);
        }

        /* Format the data chunk */
        payload = ibm_cloud_logs_compose_payload(ctx, 
                                                 event_chunk->data,
                                                 event_chunk->size,
                                                 event_chunk->tag,
                                                 flb_sds_len(event_chunk->tag),
                                                 offset, threshold, &out_offset,
                                                 &log_decoder);
        
        if (!payload) {
            flb_plg_error(ctx->ins, "cannot compose request payload");
            ret_code = FLB_ERROR;
            goto cleanup;
        }

        flb_plg_debug(ctx->ins, "the last offset of decoder is %zu", out_offset);

        payload_len = flb_sds_len(payload);

        if (payload_len >= two_mebibytes) {
            retries++;
            if (retries >= HTTP_RETRY_LIMIT) {
                flb_plg_error(ctx->ins, "Retry limit exceeded for payload composition");
                ret_code = FLB_ERROR;
                flb_sds_destroy(payload);
                goto cleanup;
            }

            flb_plg_debug(ctx->ins,
                          "HTTP request body exceeded %zu bytes. actual: %zu. left attempt(s): %d",
                          two_mebibytes, payload_len, HTTP_RETRY_LIMIT - retries);
            flb_sds_destroy(payload);
            payload = NULL;
            goto retry;
        }
        else {
            retries = 0;
        }

        flb_plg_debug(ctx->ins, "sending payload: %zu bytes to %s", 
                     payload_len, ctx->ibm_logs_path);

        /* Create HTTP client */
        http_client = flb_http_client(u_conn, FLB_HTTP_POST, ctx->ibm_logs_path,
                                      payload, payload_len,
                                      ctx->ibm_logs_host, ctx->ibm_logs_port, 
                                      NULL, 0);

        if (!http_client) {
            flb_plg_error(ctx->ins, "cannot create http client");
            ret_code = FLB_ERROR;
            flb_sds_destroy(payload);
            goto cleanup;
        }

        /* Add headers */
        flb_http_bearer_auth(http_client, ctx->auth->bearer_token);
        flb_http_add_header(http_client, "Content-Type", 12, "application/json", 16);

        /* Perform HTTP request */
        result = flb_http_do(http_client, &b_sent);

        /* Check result */
        if (result != 0) {
            flb_plg_warn(ctx->ins, "http_do=%i URI=%s", result, ctx->ibm_logs_path);
            ret_code = FLB_RETRY;
        }
        else {
            /* Validate HTTP status */
            if (http_client->resp.status == 0) {
                flb_plg_error(ctx->ins, "connection broken or no response received");
                ret_code = FLB_RETRY;
            }
            else if (http_client->resp.status < 200 || http_client->resp.status >= 300) {
                if (http_client->resp.status == 401) {
                    flb_plg_error(ctx->ins, "authentication failed (401), will retry with token refresh");
                    ctx->auth->token_expiry = 0;
                    ret_code = FLB_RETRY;
                } else if (http_client->resp.status == 429) {
                    flb_plg_warn(ctx->ins, "rate limited (429), will retry");
                    ret_code = FLB_RETRY;
                } else if (http_client->resp.status >= 500) {
                    flb_plg_warn(ctx->ins, "server error (status=%d), will retry", 
                                http_client->resp.status);
                    ret_code = FLB_RETRY;
                } else {
                    flb_plg_error(ctx->ins, "unexpected HTTP status=%d", 
                                 http_client->resp.status);
                    if (http_client->resp.payload_size > 0) {
                        flb_plg_error(ctx->ins, "server response: %.*s",
                                      (int)http_client->resp.payload_size, 
                                      http_client->resp.payload);
                    }
                    ret_code = FLB_ERROR;
                }
            }
            else {
                /* Success */
                ret_code = FLB_OK;
                
                /* Update statistics */
                int chunk_count = count_logs_with_threshold(offset, threshold, 
                                                            &log_decoder, ctx);
                ctx->total_logs_sent += chunk_count;
                ctx->total_bytes_sent += payload_len;
            }
        }

        /* Clean up HTTP client for this iteration */
        flb_sds_destroy(payload);
        payload = NULL;
        flb_http_client_destroy(http_client);
        http_client = NULL;

        /* If we got an error, bail out */
        if (ret_code != FLB_OK) {
            break;
        }

        /* Check if all chunks are processed */
        if (out_offset >= event_chunk->size) {
            need_loop = FLB_FALSE;
        }

        /* Update offset for next iteration */
        offset = out_offset;
    }

    /* Update flush count */
    ctx->flush_count++;

cleanup:
    /* Cleanup resources */
    if (payload) {
        flb_sds_destroy(payload);
    }
    if (http_client) {
        flb_http_client_destroy(http_client);
    }
    flb_log_event_decoder_destroy(&log_decoder);
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(ret_code);
}

/* Enhanced exit callback */
static int cb_ibm_logs_exit(void *data, struct flb_config *config)
{
    struct flb_ibm_logs *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_plg_info(ctx->ins, "exiting IBM Cloud Logs output plugin");

    flb_plg_info(ctx->ins, "statistics:");
    flb_plg_info(ctx->ins, "  Total logs sent: %llu", ctx->total_logs_sent);
    flb_plg_info(ctx->ins, "  Total bytes sent: %llu", ctx->total_bytes_sent);
    flb_plg_info(ctx->ins, "  Total flushes: %llu", ctx->flush_count);
    flb_plg_info(ctx->ins, "  Auth refreshes: %llu", ctx->auth_refresh_count);

    /* Clear sensitive auth data */
    ibm_auth_cleanup(ctx);

    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->auth_mutex);

    /* Free context */
    flb_free(ctx);
    
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "ibm_logs_host", NULL,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_logs_host),
     "Host of your IBM Cloud Logs instance."
    },

    {
     FLB_CONFIG_MAP_INT, "ibm_logs_port", FLB_IBM_LOGS_PORT,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_logs_port),
     "IBM Cloud Logs TCP port"
    },

    {
     FLB_CONFIG_MAP_STR, "ibm_logs_path", FLB_IBM_LOGS_PATH,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_logs_path),
     "IBM Cloud Logs URL path"
    },

    {
     FLB_CONFIG_MAP_STR, "application_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, application_name),
     "Application name to use for logs (default: ibm-application-name-not-found)"
    },

    {
     FLB_CONFIG_MAP_STR, "subsystem_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, subsystem_name),
     "Subsystem name to use for logs (default: ibm-subsystem-name-not-found)"
    },

    {
     FLB_CONFIG_MAP_STR, "ibm_iam_authentication_mode", IBM_AUTH_MODE_APIKEY,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_iam_authentication_mode),
     "IBM IAM Authentication mode, 'apikey' | 'trusted_profile'"
    },

    {
     FLB_CONFIG_MAP_STR, "ibm_iam_env", IBM_IAM_ENV_PRODUCTION,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_iam_env),
     "IBM IAM environment, 'staging' | 'production'"
    },

    {
     FLB_CONFIG_MAP_STR, "ibm_iam_trusted_profile_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_iam_trusted_profile_id),
     "IBM IAM trusted profile id"
    },

    {
     FLB_CONFIG_MAP_STR, "cr_token_mount_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, cr_token_mount_path),
     "Set CR token mount path"
    },

    /* Add terminator */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_ibm_logs_plugin = {
    .name        = "ibm_logs",
    .description = "Send events to IBM Cloud Logs",
    .cb_init     = cb_ibm_logs_init,
    .cb_flush    = cb_ibm_logs_flush,
    .cb_exit     = cb_ibm_logs_exit,

    /* Configuration */
    .config_map  = config_map,

    /* Plugin flags */
    .flags       = FLB_OUTPUT_NET | FLB_IO_TLS
};