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

    if (!ctx->subsystem_name) {
        ctx->subsystem_name = flb_sds_create(DEFAULT_SUBSYSTEM_NAME);
        if (!ctx->subsystem_name) {
            flb_plg_error(ctx->ins, "failed to allocate default subsystem name");
            goto error;
        } else {
            flb_plg_debug(ctx->ins, "default subsystem name has been set");
        }
    }

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


/* Extract application name from various sources */
static inline void extract_application_name(struct flb_ibm_logs *ctx,
                                           msgpack_object *kubernetes_map,
                                           const char *file_path,
                                           int file_path_len,
                                           flb_sds_t *app_name)
{
    /* Try to get from Kubernetes metadata namespace_name */
    if (kubernetes_map && kubernetes_map->via.map.ptr) {
        flb_plg_debug(ctx->ins, "kubernete_map->via.map.ptr != null");
        for (int j = 0; j < kubernetes_map->via.map.size; j++) {
            msgpack_object kk = kubernetes_map->via.map.ptr[j].key;
            msgpack_object vv = kubernetes_map->via.map.ptr[j].val;
            
            if (kk.type == MSGPACK_OBJECT_STR && kk.via.str.size == 14 &&
                memcmp(kk.via.str.ptr, "namespace_name", 14) == 0) {
                if (vv.type == MSGPACK_OBJECT_STR) {
                    *app_name = flb_sds_create_len(vv.via.str.ptr, vv.via.str.size);
                    if (!app_name) {
                        flb_plg_error(ctx->ins, "failed to allocate application name from 'namespace_name'");
                    } else {
                        flb_plg_debug(ctx->ins, "application name set from 'namespace_name'");
                    }
                    return;
                }
            }
        }
    }

    /* use default */
    *app_name = flb_sds_create(DEFAULT_APP_NAME);
    if (!app_name) {
        flb_plg_error(ctx->ins, "failed to allocate default application name");
    } else {
        flb_plg_debug(ctx->ins, "default application name has been set");
    }
}

/* Extract subsystem name from various sources */
static inline void extract_subsystem_name(struct flb_ibm_logs *ctx,
                                         msgpack_object *kubernetes_map,
                                         const char *file_path,
                                         int file_path_len,
                                         flb_sds_t *subsystem_name)
{
    /* Try to get from Kubernetes annotations */
    if (kubernetes_map && kubernetes_map->via.map.ptr) {
        msgpack_object *annotations_map = NULL;
        for (int j = 0; j < kubernetes_map->via.map.size; j++) {
            msgpack_object kk = kubernetes_map->via.map.ptr[j].key;
            msgpack_object vv = kubernetes_map->via.map.ptr[j].val;
            if (kk.type == MSGPACK_OBJECT_STR && kk.via.str.size == 11 &&
                memcmp(kk.via.str.ptr, "annotations", 11) == 0) {
                if (vv.type == MSGPACK_OBJECT_MAP) {
                    annotations_map = &vv;
                    break;
                }
            }
        }
        if (annotations_map && annotations_map->via.map.ptr) {
            for (int j = 0; j < annotations_map->via.map.size; j++) {
                msgpack_object kk = annotations_map->via.map.ptr[j].key;
                msgpack_object vv = annotations_map->via.map.ptr[j].val;
                if (kk.type == MSGPACK_OBJECT_STR && kk.via.str.size == 13 &&
                    memcmp(kk.via.str.ptr, "container_name", 13) == 0) {
                    if (vv.type == MSGPACK_OBJECT_STR) {
                        *subsystem_name = flb_sds_create_len(vv.via.str.ptr, vv.via.str.size);
                        return;
                    }
                }
            }
        }
    }

    /* use default */
    *subsystem_name = ctx->subsystem_name;
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
        
        /* Count additional fields we'll include */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            k = log_event.body->via.map.ptr[i].key;
            v = log_event.body->via.map.ptr[i].val;

            /* Check for kubernetes metadata */
            if (k.via.str.size == 10 && memcmp(k.via.str.ptr, "kubernetes", 10) == 0) {
                if (v.type == MSGPACK_OBJECT_MAP) {
                    kubernetes_map = &v;
                    flb_plg_debug(ctx->ins, "kubernetes map found");
                }
            }
            /* Check for file field */
            else if (k.via.str.size == 4 && memcmp(k.via.str.ptr, "file", 4) == 0) {
                if (v.type == MSGPACK_OBJECT_STR) {
                    file_path = v.via.str.ptr;
                    file_path_len = v.via.str.size;
                    flb_plg_debug(ctx->ins, "file found");
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
        
        /* applicationName - use namespace name from Kubemetadata or default */
        msgpack_pack_str(&mp_pck, 15);
        msgpack_pack_str_body(&mp_pck, "applicationName", 15);

        if (!ctx->application_name) {
            flb_plg_debug(ctx->ins, "\napplication name not provided, figuring out one ...");
            extract_application_name(ctx, kubernetes_map, file_path, file_path_len,
                                 &app_name_to_use);
            msgpack_pack_str(&mp_pck, flb_sds_len(app_name_to_use));
            msgpack_pack_str_body(&mp_pck, app_name_to_use, flb_sds_len(app_name_to_use));
        } else {
            flb_plg_debug(ctx->ins, "application name is provided from the config");
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->application_name));
            msgpack_pack_str_body(&mp_pck, ctx->application_name, flb_sds_len(ctx->application_name));
        }
        
        /* subsystemName - use container_name from Kubernetes metadata or default */
        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "subsystemName", 13);

        // extract_subsystem_name(ctx, kubernetes_map, file_path, file_path_len,
        //                         &subsystem_name_to_use);

        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->subsystem_name));
        msgpack_pack_str_body(&mp_pck, ctx->subsystem_name, flb_sds_len(ctx->subsystem_name));

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
    if (app_name_to_use != ctx->application_name) {
        flb_sds_destroy(app_name_to_use);
    }
    if (subsystem_name_to_use != ctx->subsystem_name) {
        flb_sds_destroy(subsystem_name_to_use);
    }

    return json;

error:
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (app_name_to_use != ctx->application_name) {
        flb_sds_destroy(app_name_to_use);
    }
    if (subsystem_name_to_use != ctx->subsystem_name) {
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
