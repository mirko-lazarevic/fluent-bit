/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>

#include "ibm_logs.h"
#include "ibm_auth.h"
#include "arena.h"

/* Initialize authentication context in global(plugin lifecycle) arena */
int ibm_auth_init(struct flb_ibm_logs *ctx)
{
    struct ibm_auth_context *auth;
    const char *api_key_env;

    /* Allocate auth context from global (plugin lifecycle) arena */
    auth = arena_calloc(&ctx->global_arena, 1, sizeof(struct ibm_auth_context));
    if (!auth) {
        flb_plg_error(ctx->ins, "failed to allocate auth context");
        return -1;
    }

    ctx->auth = auth;

    /* Set IAM endpoint based on environment */
    if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_STAGING) == 0) {
        auth->iam_endpoint = arena_strdup(&ctx->global_arena,
                                         "https://iam.test.cloud.ibm.com/identity/token");
    } else if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_PRODUCTION) == 0) {
        auth->iam_endpoint = arena_strdup(&ctx->global_arena,
                                         "https://iam.cloud.ibm.com/identity/token");
    } else {
        flb_plg_error(ctx->ins, "Invalid IBM IAM environment: %s", ctx->ibm_iam_env);
        return -1;
    }

    if (!auth->iam_endpoint) {
        flb_plg_error(ctx->ins, "failed to allocate IAM endpoint");
        return -1;
    }

    /* Pre-allocate and setup grant type based on auth mode */
    if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) == 0) {
        auth->grant_type = arena_strdup(&ctx->global_arena,
                                       "urn:ibm:params:oauth:grant-type:apikey");
        auth->grant_type_len = strlen(auth->grant_type);

        /* Get API key from environment */
        api_key_env = getenv(IBM_IAM_API_KEY);
        if (!api_key_env || strlen(api_key_env) == 0) {
            flb_plg_error(ctx->ins, "'%s' env variable not set or empty", IBM_IAM_API_KEY);
            return -1;
        }

        /* Store API key in global arena */
        auth->auth_value = arena_strdup(&ctx->global_arena, api_key_env);
        if (!auth->auth_value) {
            flb_plg_error(ctx->ins, "failed to allocate API key");
            return -1;
        }
        auth->auth_value_len = strlen(auth->auth_value);

        flb_plg_info(ctx->ins, "configured API key authentication");

    } else if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) == 0) {
        auth->grant_type = arena_strdup(&ctx->global_arena,
                                       "urn:ibm:params:oauth:grant-type:cr-token");
        auth->grant_type_len = strlen(auth->grant_type);

        /* Store profile ID */
        if (!ctx->ibm_iam_trusted_profile_id) {
            flb_plg_error(ctx->ins, "Trusted profile ID not configured");
            return -1;
        }

        auth->auth_value = arena_strdup(&ctx->global_arena, ctx->ibm_iam_trusted_profile_id);
        if (!auth->auth_value) {
            flb_plg_error(ctx->ins, "failed to allocate profile ID");
            return -1;
        }
        auth->auth_value_len = strlen(auth->auth_value);

        /* Store CR token path */
        if (!ctx->cr_token_mount_path) {
            flb_plg_error(ctx->ins, "CR token mount path not configured");
            return -1;
        }

        auth->cr_token_path = arena_strdup(&ctx->global_arena, ctx->cr_token_mount_path);
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
    auth->bearer_token = arena_alloc(&ctx->global_arena, MAX_TOKEN_SIZE);
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
    struct ibm_auth_context *auth = ctx->auth;
    struct flb_oauth2 *oauth2_ctx;
    flb_sds_t token = NULL;
    int result;
    char *cr_token = NULL;
    size_t cr_token_size = 0;

    if (!auth) {
        flb_plg_error(ctx->ins, "auth context not initialized");
        return -1;
    }

    flb_plg_debug(ctx->ins, "requesting new IAM token from %s", auth->iam_endpoint);

    /* Create OAuth2 context */
    oauth2_ctx = flb_oauth2_create(config, auth->iam_endpoint, 3600);
    if (!oauth2_ctx) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }

    /* Add grant type */
    result = flb_oauth2_payload_append(oauth2_ctx, "grant_type", 10,
                                      auth->grant_type, auth->grant_type_len);
    if (result == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 param 'grant_type'");
        flb_oauth2_destroy(oauth2_ctx);
        return -1;
    }

    /* Add auth-specific parameters */
    if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) == 0) {
        /* API Key mode */
        result = flb_oauth2_payload_append(oauth2_ctx, "apikey", 6,
                                          auth->auth_value, auth->auth_value_len);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'apikey'");
            flb_oauth2_destroy(oauth2_ctx);
            return -1;
        }

    } else if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) == 0) {
        /* Trusted Profile mode */
        result = flb_oauth2_payload_append(oauth2_ctx, "profile_id", 10,
                                          auth->auth_value, auth->auth_value_len);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'profile_id'");
            flb_oauth2_destroy(oauth2_ctx);
            return -1;
        }

        /* Read CR token using the standard flb_utils_read_file */
        result = flb_utils_read_file(auth->cr_token_path, &cr_token, &cr_token_size);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error reading CR token from %s", auth->cr_token_path);
            flb_oauth2_destroy(oauth2_ctx);
            return -1;
        }

        /* Check if token fits in our buffer */
        if (cr_token_size >= MAX_CR_TOKEN_SIZE) {
            flb_plg_error(ctx->ins, "CR token too large: %zu bytes", cr_token_size);
            flb_free(cr_token);
            flb_oauth2_destroy(oauth2_ctx);
            return -1;
        }

        /* Copy to our pre-allocated buffer and free the temporary allocation */
        memcpy(ctx->cr_token_buffer, cr_token, cr_token_size);
        ctx->cr_token_buffer[cr_token_size] = '\0';
        flb_free(cr_token);

        flb_plg_debug(ctx->ins, "Read CR token, size: %zu", cr_token_size);

        result = flb_oauth2_payload_append(oauth2_ctx, "cr_token", 8,
                                          ctx->cr_token_buffer, cr_token_size);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'cr_token'");
            flb_oauth2_destroy(oauth2_ctx);
            return -1;
        }
    }

    /* Get token */
    token = flb_oauth2_token_get(oauth2_ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        flb_oauth2_destroy(oauth2_ctx);
        return -1;
    }

    /* Copy token to pre-allocated buffer */
    size_t token_len = flb_sds_len(token);
    if (token_len >= MAX_TOKEN_SIZE) {
        flb_plg_error(ctx->ins, "token too large: %zu bytes", token_len);
        flb_sds_destroy(token);
        flb_oauth2_destroy(oauth2_ctx);
        return -1;
    }

    memcpy(auth->bearer_token, token, token_len);
    auth->bearer_token[token_len] = '\0';

    /* Update expiry time (OAuth2 default is 3600 seconds) */
    auth->token_expiry = time(NULL) + 3600;

    /* Cleanup */
    flb_oauth2_destroy(oauth2_ctx);

    /* Update statistics */
    ctx->auth_refresh_count++;

    flb_plg_info(ctx->ins, "Successfully obtained IAM token (refresh #%llu)",
                 ctx->auth_refresh_count);

    return 0;
}

/* Check if token needs refresh and refresh if necessary */
int ibm_auth_refresh_if_needed(struct flb_ibm_logs *ctx,
                               struct flb_config *config)
{
    int ret = 0;
    struct ibm_auth_context *auth = ctx->auth;
    time_t current_time;

    if (!auth) {
        flb_plg_error(ctx->ins, "auth context not initialized");
        return -1;
    }

    /* Check if we have a token */
    if (strlen(auth->bearer_token) == 0) {
        flb_plg_debug(ctx->ins, "no token available, requesting new one");
        return ibm_auth_get_token(ctx, config);
    }

    pthread_mutex_lock(&ctx->auth_mutex);
    /* Check if token is expired or about to expire */
    current_time = time(NULL);
    if (current_time >= (auth->token_expiry - TOKEN_REFRESH_THRESHOLD)) {
        flb_plg_debug(ctx->ins, "token expired or expiring soon, refreshing");
        ret = ibm_auth_get_token(ctx, config);
    } else {
        flb_plg_debug(ctx->ins, "token not expired, using existing one");
    }

    pthread_mutex_unlock(&ctx->auth_mutex);

    return ret;
}

/* Cleanup authentication (called on exit) */
void ibm_auth_cleanup(struct flb_ibm_logs *ctx)
{
    /* Nothing to do - memory is managed by arena
       it will be cleaned up on plugin exit    */
    if (ctx->auth && ctx->auth->bearer_token) {
        /* Clear sensitive data */
        memset(ctx->auth->bearer_token, 0, MAX_TOKEN_SIZE);
    }

    if (ctx->cr_token_buffer) {
        /* Clear sensitive data */
        memset(ctx->cr_token_buffer, 0, MAX_CR_TOKEN_SIZE);
    }
}