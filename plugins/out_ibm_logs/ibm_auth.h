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

#ifndef FLB_IBM_AUTH
#define FLB_IBM_AUTH

#define IBM_AUTH_MODE_APIKEY            "apikey"
#define IBM_AUTH_MODE_TRUSTED_PROFILE   "trusted_profile"

#define IBM_IAM_ENV_STAGING     "staging"
#define IBM_IAM_ENV_PRODUCTION  "production"

#define IBM_IAM_API_KEY         "IBM_IAM_API_KEY"

/* Token refresh threshold (5 minutes before expiry) */
#define TOKEN_REFRESH_THRESHOLD_SECONDS  300
#define TOKEN_EXPIRY_SECONDS             3600

/* String literal lengths for security */
#define GRANT_TYPE_APIKEY_LEN    31
#define GRANT_TYPE_CR_TOKEN_LEN  34

#include <fluent-bit/flb_output_plugin.h>
#include "ibm_logs.h"

/* Authentication context */
struct ibm_auth_context {
    char *bearer_token;
    time_t token_expiry;
    char *iam_endpoint;
    
    /* OAuth2 payload components (pre-allocated) */
    char *grant_type;
    size_t grant_type_len;
    char *auth_value;      /* API key or profile ID */
    size_t auth_value_len;
    char *cr_token_path;   /* For trusted profile */
};

int ibm_auth_init(struct flb_ibm_logs *ctx);
int ibm_auth_get_token(struct flb_ibm_logs *ctx, struct flb_config *config);
int ibm_auth_refresh_if_needed(struct flb_ibm_logs *ctx, struct flb_config *config);
void ibm_auth_cleanup(struct flb_ibm_logs *ctx);

#endif