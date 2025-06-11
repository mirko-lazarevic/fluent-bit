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

static int cb_ibm_logs_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_ibm_logs *ctx;
     struct flb_upstream *upstream;

    flb_plg_debug(ins, "init executed");

    /* allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_ibm_logs));
    if (!ctx) {
        flb_errno();
        flb_plg_error(ins, "configuration failed");
        return -1;
    }
    ctx->ins = ins;

    /* load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* validate mandatory properties */
    if (!ctx->ibm_logs_host) {
        flb_plg_error(ctx->ins, "property 'host' is not defined");
        flb_ibm_logs_conf_destroy(ctx);
        return -1;
    }

    /* create upstream connection context */
    upstream = flb_upstream_create(config,
                                   ctx->ibm_logs_host,
                                   ctx->ibm_logs_port,
                                   FLB_IO_TLS, ins->tls);
    
    if (!upstream) {
        flb_plg_error(ins, "upstream creation failed");
        flb_free(ctx);
        return -1;
    }

    ctx->upstream = upstream;
    flb_output_upstream_set(ctx->upstream, ins);

    /* export context */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ctx->ins, "plugin configured port=%d host=%s", ctx->ibm_logs_port, ctx->ibm_logs_host);
    return 0;
}

static inline int primary_key_check(msgpack_object k, char *name, int len)
{
    if (k.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (k.via.str.size != len) {
        return FLB_FALSE;
    }

    if (memcmp(k.via.str.ptr, name, len) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int record_append_primary_keys(struct flb_logdna *ctx,
                                      msgpack_object *map,
                                      msgpack_packer *mp_sbuf)
{
    int i;
    int c = 0;
    
    msgpack_object *application_name = NULL;
    msgpack_object *subsystem_name = NULL;
    msgpack_object *computer_name = NULL;
    msgpack_object *level = NULL;
    msgpack_object *category = NULL;
    msgpack_object *class_name = NULL;
    msgpack_object *method_name = NULL;
    msgpack_object *thread_id = NULL;
    msgpack_object *text = NULL;

    msgpack_object k;
    msgpack_object v;

    for (i = 0; i < map->via.array.size; i++) {
        k = map->via.map.ptr[i].key;
        v = map->via.map.ptr[i].val;

        // printf("\n");
        // msgpack_object_print(stdout, k);
        // printf("=>");
        // msgpack_object_print(stdout, v);
        // printf("\n");

        /* Level/Severity - optional */
        if (!level &&
            (primary_key_check(k, "level", 5) == FLB_TRUE ||
             primary_key_check(k, "severity", 8) == FLB_TRUE)) {
            level = &k;
            msgpack_pack_str(mp_sbuf, 5);
            msgpack_pack_str_body(mp_sbuf, "level", 5);
            msgpack_pack_object(mp_sbuf, v);
            c++;
        }
    }

    return c;
}

static flb_sds_t ibm_cloud_logs_compose_payload(struct flb_ibm_logs *ctx,
                                                const void *data, size_t bytes,
                                                const char *tag, int tag_len)
{
    int ret;
    int total_lines;
    int array_size = 0;
    off_t map_off;

    flb_sds_t json;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        return NULL;
    }

    /* Count number of records */
    total_lines = flb_mp_count(data, bytes);

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Main map */
    msgpack_pack_map(&mp_pck, 1);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        
        map_off = mp_sbuf.size;
        array_size = 1;
        msgpack_pack_map(&mp_pck, array_size);
        
        /* Timestamp */
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);
        msgpack_pack_int(&mp_pck, (int) flb_time_to_double(&log_event.timestamp));

        ret = record_append_primary_keys(ctx, log_event.body, &mp_pck);
        array_size += ret;

        /* Adjust map header size */
        flb_mp_set_map_header_size(mp_sbuf.data + map_off, array_size);
                
    }

    flb_log_event_decoder_destroy(&log_decoder);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}

static void cb_ibm_logs_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int result;
    flb_sds_t payload;
    struct flb_ibm_logs *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    flb_plg_debug(ctx->ins, "flush executed");

    /* Get OAuth2 token */
    result = ibm_get_token(ctx, config);
    if (result != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot obtain token");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    } else {
        flb_plg_debug(ctx->ins, "IAM token obtained");
    }

     /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Format the data to the expected IBM Cloud Logs payload */
    payload = ibm_cloud_logs_compose_payload(ctx, 
                                             event_chunk->data,
                                             event_chunk->size,
                                             event_chunk->tag,
                                             flb_sds_len(event_chunk->tag));
    
    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    printf("=========\n%s\n==========\n", payload);

    // flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_ibm_logs_exit(void *data, struct flb_config *config)
{
    struct flb_ibm_logs *ctx = data;
    flb_plg_debug(ctx->ins, "exit executed");
    
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
     FLB_CONFIG_MAP_INT, "ibm_logs_path", FLB_IBM_LOGS_PATH,
     0, FLB_TRUE, offsetof(struct flb_ibm_logs, ibm_logs_path),
     "IBM Cloud Logs URL path"
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

    flb_free(ctx);

    return 0;
}
