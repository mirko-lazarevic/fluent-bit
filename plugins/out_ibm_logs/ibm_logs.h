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

#ifndef FLB_OUT_IBM_LOGS
#define FLB_OUT_IBM_LOGS

#define FLB_IBM_LOGS_CT              "Content-Type"
#define FLB_IBM_LOGS_CT_JSON         "application/json"

#define FLB_IBM_LOGS_PORT "443"
#define FLB_IBM_LOGS_PATH "/logs/v1/singles"

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

#include "arena.h"

/* Arena sizes */
#define GLOBAL_ARENA_SIZE    (64 * 1024)     /* 64KB for global arena */
#define TEMP_ARENA_SIZE      (256 * 1024)    /* 256KB for temporary arena */

/* Pre-allocated buffer sizes */
// #define MAX_LOG_BUFFER_SIZE  (16 * 1024)     /* 16KB per log entry */
// #define MAX_BATCH_SIZE       100              /* Max logs per batch */

#define MAX_TOKEN_SIZE       (8 * 1024)      /* 8KB for bearer token */
#define MAX_CR_TOKEN_SIZE    (16 * 1024)     /* 16KB for CR token */

#define DEFAULT_APP_NAME "ibm-application-name-not-found"
#define DEFAULT_SUBSYSTEM_NAME "ibm-subsystem-name-not-found"

struct flb_ibm_logs {
    
    int       ibm_logs_port;
    flb_sds_t ibm_logs_host;
    flb_sds_t ibm_logs_path;

    /* Application and subsystem names */
    flb_sds_t application_name;
    flb_sds_t subsystem_name;

    /* Mutex for thread-safe token access */
    pthread_mutex_t auth_mutex;

    /* Authentication context (allocated from global arena) */
    struct ibm_auth_context *auth;

    flb_sds_t ibm_iam_authentication_mode;
    flb_sds_t ibm_iam_env;
    flb_sds_t ibm_iam_trusted_profile_id;
    flb_sds_t cr_token_mount_path;

    char *cr_token_buffer;     /* Buffer for CR token reading */

    /* Global arena for persistent allocations */
    struct arena global_arena;

    /* Temporary arena for per-flush allocations */
    struct arena temp_arena;

    /* upstream connection to the IBM Cloud Logs endpoint */
    struct flb_upstream *upstream;

    /* Statistics */
    uint64_t total_logs_sent;
    uint64_t total_bytes_sent;
    uint64_t flush_count;
    uint64_t auth_refresh_count;

    /* Plugin instance reference */
    struct flb_output_instance *ins;
};

#endif