/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>

#include "ibm_logs.h"
#include "ibm_auth.h"

/* String constants for better maintainability */
static const char *IAM_ENDPOINT_STAGING = "https://iam.test.cloud.ibm.com/identity/token";
static const char *IAM_ENDPOINT_PRODUCTION = "https://iam.cloud.ibm.com/identity/token";
static const char *GRANT_TYPE_APIKEY_STR = "urn:ibm:params:oauth:grant-type:apikey";
static const char *GRANT_TYPE_CR_TOKEN_STR = "urn:ibm:params:oauth:grant-type:cr-token";

/* Initialize authentication context in global arena */
int ibm_auth_init(struct flb_ibm_logs *ctx)
{
    struct ibm_auth_context *auth;
    const char *api_key_env;
    size_t api_key_len;

    if (!ctx) {
        return -1;
    }

    /* Allocate auth context */
    auth = flb_calloc(1, sizeof(struct ibm_auth_context));
    if (!auth) {
        flb_plg_error(ctx->ins, "failed to allocate auth context");
        return -1;
    }

    ctx->auth = auth;

    /* Set IAM endpoint based on environment */
    if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_STAGING) == 0) {
        auth->iam_endpoint = flb_strdup(IAM_ENDPOINT_STAGING);
    } else if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_PRODUCTION) == 0) {
        auth->iam_endpoint = flb_strdup(IAM_ENDPOINT_PRODUCTION);
    } else {
        flb_plg_error(ctx->ins, "Invalid IBM IAM environment: %s", ctx->ibm_iam_env);
        return -1;
    }

    if (!auth->iam_endpoint) {
        flb_plg_error(ctx->ins, "failed to allocate IAM endpoint");
        return -1;
    }

    /* Setup grant type based on auth mode */
    if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) == 0) {
        auth->grant_type = flb_strdup(GRANT_TYPE_APIKEY_STR);
        auth->grant_type_len = strlen(GRANT_TYPE_APIKEY_STR);

        /* Get and validate API key from environment */
        api_key_env = getenv(IBM_IAM_API_KEY);
        if (!api_key_env) {
            flb_plg_error(ctx->ins, "'%s' env variable not set", IBM_IAM_API_KEY);
            return -1;
        }
        
        api_key_len = strlen(api_key_env);
        if (api_key_len == 0 || api_key_len > MAX_API_KEY_SIZE) {
            flb_plg_error(ctx->ins, "Invalid API key length: %zu", api_key_len);
            return -1;
        }

        /* Store API key in global arena */
        auth->auth_value = flb_strdup(api_key_env);
        if (!auth->auth_value) {
            flb_plg_error(ctx->ins, "failed to allocate API key");
            return -1;
        }
        auth->auth_value_len = api_key_len;

        flb_plg_info(ctx->ins, "configured API key authentication");

    } else if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) == 0) {
        auth->grant_type = flb_strdup(GRANT_TYPE_CR_TOKEN_STR);
        auth->grant_type_len = strlen(GRANT_TYPE_CR_TOKEN_STR);

        /* Validate and store profile ID */
        if (!ctx->ibm_iam_trusted_profile_id || 
            strlen(ctx->ibm_iam_trusted_profile_id) == 0 ||
            strlen(ctx->ibm_iam_trusted_profile_id) > MAX_PROFILE_ID_SIZE) {
            flb_plg_error(ctx->ins, "Invalid trusted profile ID");
            return -1;
        }

        auth->auth_value = flb_strdup(ctx->ibm_iam_trusted_profile_id);
        if (!auth->auth_value) {
            flb_plg_error(ctx->ins, "failed to allocate profile ID");
            return -1;
        }
        auth->auth_value_len = strlen(ctx->ibm_iam_trusted_profile_id);

        /* Validate and store CR token path */
        if (!ctx->cr_token_mount_path || strlen(ctx->cr_token_mount_path) == 0) {
            flb_plg_error(ctx->ins, "CR token mount path not configured");
            return -1;
        }

        auth->cr_token_path = flb_strdup(ctx->cr_token_mount_path);
        if (!auth->cr_token_path) {
            flb_plg_error(ctx->ins, "failed to allocate CR token path");
            return -1;
        }

        flb_plg_info(ctx->ins, "Configured trusted profile authentication");

    } else {
        flb_plg_error(ctx->ins, "Invalid IBM auth mode: %s", ctx->ibm_iam_authentication_mode);
        return -1;
    }

    /* Pre-allocate token buffer in global arena */
    auth->bearer_token = flb_calloc(1, MAX_TOKEN_SIZE);
    if (!auth->bearer_token) {
        flb_plg_error(ctx->ins, "failed to allocate token buffer");
        return -1;
    }

    /* Initialize with empty token */
    auth->bearer_token[0] = '\0';
    auth->token_expiry = 0;

    return 0;
}

/* Get or refresh authentication token */
int ibm_auth_get_token(struct flb_ibm_logs *ctx, struct flb_config *config)
{
    struct ibm_auth_context *auth;
    struct flb_oauth2 *oauth2_ctx = NULL;
    flb_sds_t token = NULL;
    int result = -1;
    char *cr_token = NULL;
    size_t cr_token_size = 0;
    size_t token_len;

    if (!ctx || !ctx->auth) {
        return -1;
    }

    auth = ctx->auth;

    flb_plg_debug(ctx->ins, "requesting new IAM token from %s", auth->iam_endpoint);

    /* Create OAuth2 context */
    oauth2_ctx = flb_oauth2_create(config, auth->iam_endpoint, TOKEN_EXPIRY_SECONDS);
    if (!oauth2_ctx) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }

    /* Add grant type */
    if (flb_oauth2_payload_append(oauth2_ctx, "grant_type", 10,
                                  auth->grant_type, auth->grant_type_len) == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 param 'grant_type'");
        goto cleanup;
    }

    /* Add auth-specific parameters */
    if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) == 0) {
        /* API Key mode */
        if (flb_oauth2_payload_append(oauth2_ctx, "apikey", 6,
                                      auth->auth_value, auth->auth_value_len) == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'apikey'");
            goto cleanup;
        }

    } else if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) == 0) {
        /* Trusted Profile mode */
        if (flb_oauth2_payload_append(oauth2_ctx, "profile_id", 10,
                                      auth->auth_value, auth->auth_value_len) == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'profile_id'");
            goto cleanup;
        }

        /* Read and validate CR token */
        if (flb_utils_read_file(auth->cr_token_path, &cr_token, &cr_token_size) == -1) {
            flb_plg_error(ctx->ins, "error reading CR token from %s", auth->cr_token_path);
            goto cleanup;
        }

        /* Validate token size */
        if (cr_token_size == 0 || cr_token_size >= MAX_CR_TOKEN_SIZE) {
            flb_plg_error(ctx->ins, "Invalid CR token size: %zu", cr_token_size);
            goto cleanup;
        }

        /* Copy to pre-allocated buffer */
        memcpy(ctx->cr_token_buffer, cr_token, cr_token_size);
        ctx->cr_token_buffer[cr_token_size] = '\0';

        flb_plg_debug(ctx->ins, "Read CR token, size: %zu", cr_token_size);

        if (flb_oauth2_payload_append(oauth2_ctx, "cr_token", 8,
                                      ctx->cr_token_buffer, cr_token_size) == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'cr_token'");
            goto cleanup;
        }
    }

    /* Get token */
    token = flb_oauth2_token_get(oauth2_ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        goto cleanup;
    }

    /* Validate and copy token to pre-allocated buffer */
    token_len = flb_sds_len(token);
    if (token_len == 0 || token_len >= MAX_TOKEN_SIZE) {
        flb_plg_error(ctx->ins, "Invalid token size: %zu", token_len);
        goto cleanup;
    }

    memcpy(auth->bearer_token, token, token_len);
    auth->bearer_token[token_len] = '\0';

    /* Update expiry time */
    auth->token_expiry = time(NULL) + TOKEN_EXPIRY_SECONDS;

    /* Update statistics */
    ctx->auth_refresh_count++;

    flb_plg_info(ctx->ins, "Successfully obtained IAM token (refresh #%llu)",
                 ctx->auth_refresh_count);

    result = 0;

cleanup:
    if (cr_token) {
        /* Securely clear CR token from memory */
        memset(cr_token, 0, cr_token_size);
        flb_free(cr_token);
    }

    if (oauth2_ctx) {
        flb_oauth2_destroy(oauth2_ctx);
    }

    return result;
}

/* Check if token needs refresh and refresh if necessary */
int ibm_auth_refresh_if_needed(struct flb_ibm_logs *ctx,
                               struct flb_config *config)
{
    int ret = 0;
    struct ibm_auth_context *auth;
    time_t current_time;

    if (!ctx || !ctx->auth) {
        return -1;
    }

    auth = ctx->auth;

    /* Check if we have a token */
    if (strlen(auth->bearer_token) == 0) {
        flb_plg_debug(ctx->ins, "no token available, requesting new one");
        return ibm_auth_get_token(ctx, config);
    }

    pthread_mutex_lock(&ctx->auth_mutex);
    
    /* Check if token is expired or about to expire */
    current_time = time(NULL);
    if (current_time >= (auth->token_expiry - TOKEN_REFRESH_THRESHOLD_SECONDS)) {
        flb_plg_debug(ctx->ins, "token expired or expiring soon, refreshing");
        ret = ibm_auth_get_token(ctx, config);
    } else {
        flb_plg_debug(ctx->ins, "token valid for %ld more seconds", 
                     auth->token_expiry - current_time);
    }

    pthread_mutex_unlock(&ctx->auth_mutex);

    return ret;
}

/* Cleanup authentication */
void ibm_auth_cleanup(struct flb_ibm_logs *ctx)
{
    if (ctx && ctx->auth && ctx->auth->bearer_token) {
        /* Securely clear sensitive data */
        memset(ctx->auth->bearer_token, 0, MAX_TOKEN_SIZE);
        flb_free(ctx->auth->bearer_token);
        ctx->auth->bearer_token = NULL;
    }

    if (ctx && ctx->cr_token_buffer) {
        /* Securely clear sensitive data */
        memset(ctx->cr_token_buffer, 0, MAX_CR_TOKEN_SIZE);
        flb_free(ctx->cr_token_buffer);
    }

    if (ctx->auth->iam_endpoint) {
        flb_free(ctx->auth->iam_endpoint);
    }
    
    if (ctx->auth->grant_type) {
        flb_free(ctx->auth->grant_type);
    }
    
    if (ctx->auth->cr_token_path) {
        flb_free(ctx->auth->cr_token_path);
    }

    if (ctx && ctx->auth) {
        flb_free(ctx->auth);
        ctx->auth = NULL;
    }
}