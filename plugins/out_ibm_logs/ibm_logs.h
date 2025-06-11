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

#define FLB_IBM_LOGS_PORT "443"
#define FLB_IBM_LOGS_PATH "/logs/v1/singles"

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

struct flb_ibm_logs {
    
    int       ibm_logs_port;
    flb_sds_t ibm_logs_host;
    flb_sds_t ibm_logs_path;

    /* IBM IAM Auth*/
    /* Bearer Token Auth */
    flb_sds_t bearer_token;

    flb_sds_t ibm_iam_authentication_mode;
    flb_sds_t ibm_iam_env;
    flb_sds_t ibm_iam_trusted_profile_id;
    flb_sds_t cr_token_mount_path;

    /* upstream connection to the IBM Cloud Logs endpoint */
    struct flb_upstream *upstream;

    /* Plugin instance reference */
    struct flb_output_instance *ins;
};

int flb_ibm_logs_conf_destroy(struct flb_ibm_logs *ctx);

#endif