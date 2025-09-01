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

int flb_ibm_logs_conf_destroy(struct flb_ibm_logs *ctx)
{
    if (!ctx) {
        return -1;
    }

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

    /* Destroy mutex if it was initialized */
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

    /* allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_ibm_logs));
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }
    ctx->ins = ins;

    /* initialize mutex  */
    ret = pthread_mutex_init(&ctx->auth_mutex, NULL);
    if (ret != 0) {
        flb_plg_error(ins, "failed to initialize auth mutex: %s", strerror(ret));
        flb_free(ctx);
        return -1;
    }

    /* initialize global(plugin) arena */
    ret = arena_init(&ctx->global_arena, GLOBAL_ARENA_SIZE);
    if (ret != 0) {
        flb_plg_error(ins, "failed to initialize global arena");
        flb_free(ctx);
        return -1;
    }

    /* initialize temporary arena */
    ret = arena_init(&ctx->temp_arena, TEMP_ARENA_SIZE);
    if (ret != 0) {
        flb_plg_error(ins, "failed to initialize temporary arena");
        arena_destroy(&ctx->global_arena);
        flb_free(ctx);
        return -1;
    }

    /* load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        goto error;
    }

    /* validate mandatory properties */

    // validate port
    if (ctx->ibm_logs_port <= 0 || ctx->ibm_logs_port > 65535) {
        flb_plg_error(ctx->ins, "invalid port number: %d", ctx->ibm_logs_port);
        goto error;
    }

    // validate host
    if (!ctx->ibm_logs_host || strlen(ctx->ibm_logs_host) == 0) {
        flb_plg_error(ctx->ins, "host cannot be empty");
        goto error;
    }

    // validate authentication mode
    if (strcmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) != 0 &&
        strcmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) != 0) {
        flb_plg_error(ctx->ins, "invalid authentication mode: %s",
                      ctx->ibm_iam_authentication_mode);
        return -1;
    }

    /* set default value for path if not provided */
    if(!ctx->ibm_logs_path) {
        ctx->ibm_logs_path = flb_sds_create(FLB_IBM_LOGS_PATH);
        if (!ctx->ibm_logs_path) {
            flb_plg_error(ctx->ins, "failed to allocate default ibm logs path");
            goto error;
        }
    }

    /* set default values for application_name and subsystem_name if not provided */
    /* TODO */
    // if (!ctx->application_name) {
    //     ctx->application_name = flb_sds_create(DEFAULT_APP_NAME);
    //     if (!ctx->application_name) {
    //         flb_plg_error(ctx->ins, "failed to allocate default application name");
    //         goto error;
    //     }
    // }

    // if (!ctx->subsystem_name) {
    //     ctx->subsystem_name = flb_sds_create(DEFAULT_SUBSYSTEM_NAME);
    //     if (!ctx->subsystem_name) {
    //         flb_plg_error(ctx->ins, "failed to allocate default subsystem name");
    //         goto error;
    //     } else {
    //         flb_plg_debug(ctx->ins, "default subsystem name has been set");
    //     }
    // }

    /* create upstream connection context */
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


    /* Pre-allocate token buffers */
    ctx->cr_token_buffer = arena_alloc(&ctx->global_arena, MAX_CR_TOKEN_SIZE);
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


    /* export context */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ctx->ins, "plugin configured port=%d host=%s", ctx->ibm_logs_port, ctx->ibm_logs_host);

    /* Log arena statistics */
    size_t used, available;
    arena_stats(&ctx->global_arena, &used, &available);

    flb_plg_info(ins, "global arena: %zu bytes used, %zu bytes available",
                 used, available);

    flb_plg_info(ins, "IBM Cloud Logs plugin initialized successfully");

    return 0;

error:
    arena_destroy(&ctx->temp_arena);
    arena_destroy(&ctx->global_arena);
    flb_ibm_logs_conf_destroy(ctx);
    return -1;

}

/* Extract namespace from Kubernetes log file path
 * Format: /var/log/containers/<pod>_<namespace>_<container-name>-<container-id>.log
 * Returns: newly allocated string or NULL on failure
 */
static char* parse_namespace_from_path(struct flb_ibm_logs *ctx, 
                                       const char *file_path, 
                                       int file_path_len)
{
    const char *containers_prefix = "/var/log/containers/";
    const int prefix_len = 20; /* strlen("/var/log/containers/") */
    char *namespace_start;
    char *namespace_end;
    int namespace_len;
    char *result;
    
    /* Validate input */
    if (!file_path || file_path_len <= prefix_len) {
        return NULL;
    }
    
    /* Check if path starts with expected prefix */
    if (strncmp(file_path, containers_prefix, prefix_len) != 0) {
        return NULL;
    }
    
    /* Find first underscore after prefix (end of pod name) */
    namespace_start = memchr(file_path + prefix_len, '_', 
                             file_path_len - prefix_len);
    if (!namespace_start) {
        return NULL;
    }
    namespace_start++; /* Move past the underscore */
    
    /* Find second underscore (end of namespace) */
    namespace_end = memchr(namespace_start, '_', 
                          file_path_len - (namespace_start - file_path));
    if (!namespace_end) {
        return NULL;
    }
    
    namespace_len = namespace_end - namespace_start;
    if (namespace_len <= 0 || namespace_len > 253) { /* K8s namespace max length */
        return NULL;
    }
    
    /* Allocate and copy namespace */
    result = flb_sds_create_len(namespace_start, namespace_len);
    if (!result) {
        flb_plg_error(ctx->ins, "Failed to allocate namespace from path");
    }
    
    return result;
}

/* Extract container name from Kubernetes log file path
 * Format: /var/log/containers/<pod>_<namespace>_<container-name>-<container-id>.log
 * Container name is between the second '_' and the LAST '-' before .log
 * Returns: newly allocated string or NULL on failure
 */
static char* parse_container_from_path(struct flb_ibm_logs *ctx,
                                       const char *file_path,
                                       int file_path_len)
{
    const char *containers_prefix = "/var/log/containers/";
    const int prefix_len = 20; /* strlen("/var/log/containers/") */
    const char *log_suffix = ".log";
    const int suffix_len = 4; /* strlen(".log") */
    char *container_start;
    char *container_end;
    char *last_hyphen;
    int container_len;
    char *result;
    int underscore_count = 0;
    int i;
    
    /* Validate input */
    if (!file_path || file_path_len <= (prefix_len + suffix_len)) {
        return NULL;
    }
    
    /* Check if path starts with expected prefix */
    if (strncmp(file_path, containers_prefix, prefix_len) != 0) {
        return NULL;
    }
    
    /* Check if path ends with .log */
    if (strncmp(file_path + file_path_len - suffix_len, log_suffix, suffix_len) != 0) {
        return NULL;
    }
    
    /* Find the second underscore (after pod and namespace) */
    container_start = (char *)(file_path + prefix_len);
    for (i = 0; i < file_path_len - prefix_len; i++) {
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
    
    /* Find the LAST hyphen before .log extension
     * This separates container name from container ID
     * We search backwards from the .log extension
     */
    last_hyphen = NULL;
    for (i = file_path_len - suffix_len - 1; i >= (container_start - file_path); i--) {
        if (file_path[i] == '-') {
            last_hyphen = (char *)&file_path[i];
            break;
        }
    }
    
    if (!last_hyphen || last_hyphen <= container_start) {
        /* No hyphen found or hyphen is before container start */
        return NULL;
    }
    
    container_end = last_hyphen;
    container_len = container_end - container_start;
    
    /* Validate container name length */
    if (container_len <= 0 || container_len > 253) { /* Reasonable max length */
        return NULL;
    }
    
    /* Additional validation: container name should not be just the container ID
     * Container IDs are typically 64 character hex strings
     * A valid container name with hyphens should be shorter or non-hex
     */
    if (container_len == 64) {
        /* Check if it's all hex characters (likely a container ID without name) */
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
            /* Looks like a container ID without a name prefix */
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

/* Extract application name from various sources following priority order:
 * 1. User configuration (handled by caller)
 * 2. Kubernetes metadata namespace_name
 * 3. Parsed from file path
 * 4. Default value
 */
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
    
    /* Ensure output pointer is valid */
    if (!app_name) {
        flb_plg_error(ctx->ins, "Invalid app_name pointer");
        return;
    }
    
    /* Initialize to NULL */
    *app_name = NULL;
    
    /* Priority 1: Configuration - handled by caller */
    
    /* Priority 2: Try Kubernetes metadata namespace_name */
    if (kubernetes_map && kubernetes_map->type == MSGPACK_OBJECT_MAP) {
        for (j = 0; j < kubernetes_map->via.map.size; j++) {
            k = kubernetes_map->via.map.ptr[j].key;
            v = kubernetes_map->via.map.ptr[j].val;
            
            if (k.type == MSGPACK_OBJECT_STR && 
                k.via.str.size == 14 &&
                memcmp(k.via.str.ptr, "namespace_name", 14) == 0) {
                
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
                break; /* namespace_name found but invalid/allocation failed */
            }
        }
    }
    
    /* Priority 3: Try parsing from file path */
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
    
    /* Priority 4: Fall back to default */
    *app_name = flb_sds_create(DEFAULT_APP_NAME);
    if (!*app_name) {
        flb_plg_error(ctx->ins, "Critical: Failed to allocate default application name");
        /* This is a critical error - the caller should check for NULL */
    } else {
        flb_plg_debug(ctx->ins, "Using default application name: %s", *app_name);
    }
}

/* Extract subsystem name from various sources following priority order:
 * 1. User configuration (handled by caller)
 * 2. Kubernetes annotations container_name
 * 3. Parsed from file path
 * 4. Default value
 */
static void extract_subsystem_name(struct flb_ibm_logs *ctx,
                                  msgpack_object *kubernetes_map,
                                  const char *file_path,
                                  int file_path_len,
                                  flb_sds_t *subsystem_name)
{
    msgpack_object *annotations_map = NULL;
    int j;
    msgpack_object k;
    msgpack_object v;
    char *parsed_container = NULL;
    
    /* Ensure output pointer is valid */
    if (!subsystem_name) {
        flb_plg_error(ctx->ins, "Invalid subsystem_name pointer");
        return;
    }
    
    /* Initialize to NULL */
    *subsystem_name = NULL;
    
    /* Priority 1: Configuration - handled by caller */
    
    /* Priority 2: Try Kubernetes metadata container_name */
    if (kubernetes_map && kubernetes_map->type == MSGPACK_OBJECT_MAP) {
        for (j = 0; j < kubernetes_map->via.map.size; j++) {
            k = kubernetes_map->via.map.ptr[j].key;
            v = kubernetes_map->via.map.ptr[j].val;
            
            if (k.type == MSGPACK_OBJECT_STR && 
                k.via.str.size == 14 &&
                memcmp(k.via.str.ptr, "container_name", 14) == 0) {
                
                if (v.type == MSGPACK_OBJECT_STR && v.via.str.size > 0) {
                    *subsystem_name = flb_sds_create_len(v.via.str.ptr, 
                                                            v.via.str.size);
                    if (*subsystem_name) {
                        flb_plg_debug(ctx->ins, 
                                        "Subsystem name set from container_name: %s", 
                                        *subsystem_name);
                        return;
                    }
                    flb_plg_error(ctx->ins, 
                                    "Failed to allocate subsystem name from container_name");
                }
                break; /* container_name found but invalid/allocation failed */
            }
        }
    }
    
    /* Priority 3: Try parsing from file path */
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
    
    /* Priority 4: Fall back to default */
    *subsystem_name = flb_sds_create(DEFAULT_SUBSYSTEM_NAME);
    if (!*subsystem_name) {
        flb_plg_error(ctx->ins, "Critical: Failed to allocate default subsystem name");
        /* This is a critical error - the caller should check for NULL */
    } else {
        flb_plg_debug(ctx->ins, "Using default subsystem name: %s", *subsystem_name);
    }
}

static int count_logs_with_threshold(size_t last_offset, size_t threshold,
                                    struct flb_log_event_decoder *log_decoder,
                                    struct flb_ibm_logs *ctx)
{
    int ret;
    int array_size = 0;
    size_t off = 0;
    struct flb_log_event log_event;

    /* Adjust decoder offset */
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

    /* Reset the decoder to the beginning of the data */
    flb_log_event_decoder_reset(log_decoder, (char *) data, bytes);

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Create array of log objects (as required by IBM Cloud Logs API) */
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
        
        /* Count additional fields we'll include */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            k = log_event.body->via.map.ptr[i].key;
            v = log_event.body->via.map.ptr[i].val;

            /* Check for kubernetes metadata */
            if (k.type == MSGPACK_OBJECT_STR &&
                k.via.str.size == 10 && 
                memcmp(k.via.str.ptr, "kubernetes", 10) == 0) {
                if (v.type == MSGPACK_OBJECT_MAP) {
                    kubernetes_map = &v;
                }
            }
            /* Check for file field */
            else if (k.type == MSGPACK_OBJECT_STR &&
                     k.via.str.size == 4 && 
                     memcmp(k.via.str.ptr, "file", 4) == 0) {
                if (v.type == MSGPACK_OBJECT_STR) {
                    file_path = v.via.str.ptr;
                    file_path_len = v.via.str.size;
                }
            }

            if (k.type == MSGPACK_OBJECT_STR) {
                /* Check for optional fields we want to map */
                if ((k.via.str.size == 5 && memcmp(k.via.str.ptr, "level", 5) == 0) ||
                    (k.via.str.size == 8 && memcmp(k.via.str.ptr, "severity", 8) == 0) ||
                    (k.via.str.size == 12 && memcmp(k.via.str.ptr, "computerName", 12) == 0) ||
                    (k.via.str.size == 8 && memcmp(k.via.str.ptr, "category", 8) == 0) ||
                    (k.via.str.size == 9 && memcmp(k.via.str.ptr, "className", 9) == 0) ||
                    (k.via.str.size == 10 && memcmp(k.via.str.ptr, "methodName", 10) == 0) ||
                    (k.via.str.size == 8 && memcmp(k.via.str.ptr, "threadId", 8) == 0)) {
                    fields_count++;
                }
            }
        }

        /* Add timestamp field */
        fields_count++;
        
        /* Create log object map */
        msgpack_pack_map(&mp_pck, fields_count);

        /* Required fields */
        
        /* applicationName - use configured value or extract from metadata/path */
        msgpack_pack_str(&mp_pck, 15);
        msgpack_pack_str_body(&mp_pck, "applicationName", 15);

        if (ctx->application_name) {
            app_name_to_use = ctx->application_name;
            flb_plg_debug(ctx->ins, "application name is provided from the config");
        } else {
            extract_application_name(ctx, kubernetes_map, file_path, file_path_len,
                                    &app_name_to_use);
            should_free_app_name = 1;
            
            /* Check for allocation failure */
            if (!app_name_to_use) {
                flb_plg_error(ctx->ins, "Failed to extract application name");
                goto error;
            }
            flb_plg_debug(ctx->ins, "application name=%s", app_name_to_use);
        }
        
        msgpack_pack_str(&mp_pck, flb_sds_len(app_name_to_use));
        msgpack_pack_str_body(&mp_pck, app_name_to_use, flb_sds_len(app_name_to_use));
        
        /* subsystemName - use configured value or extract from metadata/path */
        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "subsystemName", 13);

        if (ctx->subsystem_name) {
            subsystem_name_to_use = ctx->subsystem_name;
            flb_plg_debug(ctx->ins, "subsystem name is provided from the config");
        } else {
            extract_subsystem_name(ctx, kubernetes_map, file_path, file_path_len,
                                  &subsystem_name_to_use);
            should_free_subsystem_name = 1;
            
            /* Check for allocation failure */
            if (!subsystem_name_to_use) {
                flb_plg_error(ctx->ins, "Failed to extract subsystem name");
                if (should_free_app_name && app_name_to_use) {
                    flb_sds_destroy(app_name_to_use);
                }
                goto error;
            }
            flb_plg_debug(ctx->ins, "subsystem name=%s", subsystem_name_to_use);
        }
        
        msgpack_pack_str(&mp_pck, flb_sds_len(subsystem_name_to_use));
        msgpack_pack_str_body(&mp_pck, subsystem_name_to_use, flb_sds_len(subsystem_name_to_use));

        /* text - the actual log message */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "text", 4);
        /* Pack the entire log record as the text field */
        msgpack_pack_object(&mp_pck, *log_event.body);

        /* timestamp - convert to UTC milliseconds */
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);
        msgpack_pack_uint64(&mp_pck, (uint64_t)(flb_time_to_double(&log_event.timestamp) * 1000));

        /* Optional fields from log record */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            k = log_event.body->via.map.ptr[i].key;
            v = log_event.body->via.map.ptr[i].val;

            if (k.type == MSGPACK_OBJECT_STR) {

                /* Map level/severity to severity field */
                if ((k.via.str.size == 5 && memcmp(k.via.str.ptr, "level", 5) == 0) ||
                    (k.via.str.size == 8 && memcmp(k.via.str.ptr, "severity", 8) == 0)) {
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "severity", 8);
                    msgpack_pack_object(&mp_pck, v);
                }
                
                /* Map other optional fields directly */
                else if ((k.via.str.size == 12 && memcmp(k.via.str.ptr, "computerName", 12) == 0) ||
                         (k.via.str.size == 8 && memcmp(k.via.str.ptr, "category", 8) == 0) ||
                         (k.via.str.size == 9 && memcmp(k.via.str.ptr, "className", 9) == 0) ||
                         (k.via.str.size == 10 && memcmp(k.via.str.ptr, "methodName", 10) == 0) ||
                         (k.via.str.size == 8 && memcmp(k.via.str.ptr, "threadId", 8) == 0)) {
                    msgpack_pack_object(&mp_pck, k);
                    msgpack_pack_object(&mp_pck, v);
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

static void cb_ibm_logs_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int result;
    int ret_code = FLB_RETRY;
    size_t payload_len;
    flb_sds_t payload;
    size_t b_sent;
    struct flb_ibm_logs *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *http_client;
    struct flb_log_event_decoder log_decoder;

    /* IBM Logs has 2MB limit, use 1.6MB threshold for safety */
    size_t threshold = 1.6 * 1024 * 1024;
    size_t offset = 0;
    size_t out_offset = 0;
    int need_loop = FLB_TRUE;
    const int retry_limit = 8;
    int retries = 0;
    const size_t two_mebibytes = 2 * 1024 * 1024;

    size_t temp_used_before, temp_used_after;

    /* Get arena usage before flush */
    arena_stats(&ctx->temp_arena, &temp_used_before, NULL);

    flb_plg_debug(ctx->ins, "flush: processing %zu bytes of data", event_chunk->size);

    /* Reset temporary arena for this flush cycle */
    arena_reset(&ctx->temp_arena);

    /* Refresh token if needed before sending logs */
    result = ibm_auth_refresh_if_needed(ctx, config);
    if (result != 0) {
        flb_errno();
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
    result = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);
    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", result);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while (need_loop) {
    retry:
        if (retries > 0) {
            /* Reduce threshold based on retry count */
            threshold = (retry_limit - retries)/10.0 * two_mebibytes;
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
            flb_upstream_conn_release(u_conn);
            flb_log_event_decoder_destroy(&log_decoder);

            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        // flb_plg_info(ctx->ins, "payload:\n%s\n\n", payload);

        flb_plg_debug(ctx->ins, "the last offset of decoder is %zu", out_offset);

        payload_len = flb_sds_len(payload);

        if (payload_len >= two_mebibytes) {
            retries++;
            if (retries >= retry_limit) {
                flb_plg_error(ctx->ins, "Retry limit exceeded for payload composition");
                flb_upstream_conn_release(u_conn);
                flb_sds_destroy(payload);
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            flb_plg_debug(ctx->ins,
                          "HTTP request body exceeded %zd bytes. actual: %zu. left attempt(s): %d",
                          two_mebibytes, payload_len, retry_limit - retries);
            flb_sds_destroy(payload);
            goto retry;
        }
        else {
            retries = 0;
        }

        flb_plg_debug(ctx->ins, "sending payload: %zu bytes to %s", payload_len, ctx->ibm_logs_path);

        /* Create HTTP client */
        http_client = flb_http_client(u_conn, FLB_HTTP_POST, ctx->ibm_logs_path,
                            payload, payload_len,
                            ctx->ibm_logs_host, ctx->ibm_logs_port, NULL, 0);

        if (!http_client) {
            flb_plg_error(ctx->ins, "cannot create http client");
            flb_sds_destroy(payload);
            flb_upstream_conn_release(u_conn);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Compose and append Authorization header */
        flb_http_bearer_auth(http_client, ctx->auth->bearer_token);

        /* Add Content-Type header */
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
                    flb_plg_warn(ctx->ins, "server error (status=%d), will retry", http_client->resp.status);
                    ret_code = FLB_RETRY;
                } else {
                    flb_plg_error(ctx->ins, "unexpected HTTP status=%d", http_client->resp.status);
                    if (http_client->resp.payload_size > 0) {
                        flb_plg_error(ctx->ins, "server response: %.*s",
                                      (int)http_client->resp.payload_size, http_client->resp.payload);
                    }
                    ret_code = FLB_ERROR;
                }
            }
            else {
                /* Success */
                ret_code = FLB_OK;
                
                /* Update statistics for this chunk */
                int chunk_count = count_logs_with_threshold(offset, threshold, &log_decoder, ctx);
                ctx->total_logs_sent += chunk_count;
            }
        }

        /* Clean up HTTP client for this iteration */
        flb_sds_destroy(payload);
        flb_http_client_destroy(http_client);

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

    /* Get arena usage after flush */
    arena_stats(&ctx->temp_arena, &temp_used_after, NULL);
    flb_plg_debug(ctx->ins, "temp arena usage: %zu bytes (was %zu bytes)",
                  temp_used_after, temp_used_before);

    /* Cleanup */
    flb_log_event_decoder_destroy(&log_decoder);
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_ibm_logs_exit(void *data, struct flb_config *config)
{
    struct flb_ibm_logs *ctx = data;
    size_t global_used, temp_used;

    if (!ctx) {
        return 0;
    }

    flb_plg_info(ctx->ins, "exiting IBM Cloud Logs output plugin");

    /* Log final statistics */
    arena_stats(&ctx->global_arena, &global_used, NULL);
    arena_stats(&ctx->temp_arena, &temp_used, NULL);

    flb_plg_info(ctx->ins, "statistics:");
    // TODO
    flb_plg_info(ctx->ins, "  Total logs sent: %llu", ctx->total_logs_sent);
    flb_plg_info(ctx->ins, "  Total flushes: %llu", ctx->flush_count);
    flb_plg_info(ctx->ins, "  global arena final usage: %zu bytes", global_used);
    flb_plg_info(ctx->ins, "  temp arena peak usage: %zu bytes", temp_used);

    /* Destroy arenas */
    arena_destroy(&ctx->temp_arena);
    arena_destroy(&ctx->global_arena);

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
