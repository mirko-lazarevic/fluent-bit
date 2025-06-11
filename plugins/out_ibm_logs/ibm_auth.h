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

#define IBM_IAM_CT              "Content-Type"
#define IBM_IAM_CT_JSON         "application/x-www-form-urlencoded; charset=UTF-8"


#include <fluent-bit/flb_output_plugin.h>
#include "ibm_logs.h"

int ibm_get_token(struct flb_ibm_logs *ctx, struct flb_config *config);

#endif