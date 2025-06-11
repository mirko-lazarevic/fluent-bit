#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_utils.h>

#include "ibm_auth.h"

int ibm_get_token(struct flb_ibm_logs *ctx, struct flb_config *config)
{
    int result;
    char *ibm_host;
    char *ibm_api_key;
    char *cr_token;
    struct flb_oauth2 *oauth2_ctx;

    if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_STAGING) == 0) {
        ibm_host = "https://iam.test.cloud.ibm.com/identity/token";
    } else if (strcasecmp(ctx->ibm_iam_env, IBM_IAM_ENV_PRODUCTION) == 0) {
        ibm_host = "https://iam.cloud.ibm.com/identity/token";
    } else {
        // Handle invalid IBM environment
        flb_plg_error(ctx->ins, "invalid IBM environment");
        flb_ibm_logs_conf_destroy(ctx);
        return -1;
    }

    oauth2_ctx = flb_oauth2_create(config, ibm_host, 3600);
    if (!oauth2_ctx) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        flb_ibm_logs_conf_destroy(ctx);
        return -1;
    }

    if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_APIKEY) == 0) { // API Key authorization
        flb_plg_debug(ctx->ins, "using IAM api key to obtain tokens");
        result = flb_oauth2_payload_append(oauth2_ctx, "grant_type", 10, "urn:ibm:params:oauth:grant-type:apikey", 38);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'grant_type'");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

        ibm_api_key = getenv(IBM_IAM_API_KEY);
        if (!ibm_api_key || strlen(ibm_api_key) <= 0) {
            flb_plg_error(ctx->ins, "'IBM_IAM_API_KEY' env variable not set or empty");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

        result = flb_oauth2_payload_append(oauth2_ctx, "apikey", 6, ibm_api_key, strlen(ibm_api_key));
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'api_key'");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

    } else if (strcasecmp(ctx->ibm_iam_authentication_mode, IBM_AUTH_MODE_TRUSTED_PROFILE) == 0) { // Trusted Profile authorization
        flb_plg_debug(ctx->ins, "using IAM Trusted Profile to obtain tokens");

        result = flb_oauth2_payload_append(oauth2_ctx, "grant_type", 10, "urn:ibm:params:oauth:grant-type:cr-token", 40);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'grant_type'");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

        result = flb_oauth2_payload_append(oauth2_ctx, "profile_id", 10, ctx->ibm_iam_trusted_profile_id, strlen(ctx->ibm_iam_trusted_profile_id));
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'profile_id'");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

        flb_plg_debug(ctx->ins, "about to read file from path %s", ctx->cr_token_mount_path);
        size_t cr_token_size;
        result = flb_utils_read_file(ctx->cr_token_mount_path, &cr_token, &cr_token_size);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error reading token from %s", ctx->cr_token_mount_path);
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

        flb_plg_debug(ctx->ins, "%s\nsize[%zu]", cr_token, cr_token_size);
        result = flb_oauth2_payload_append(oauth2_ctx, "cr_token", 8, cr_token, cr_token_size);
        if (result == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 param 'cr_token'");
            flb_ibm_logs_conf_destroy(ctx);
            return -1;
        }

    } else {
        // Handle invalid IBM auth mode
        flb_plg_error(ctx->ins, "invalid IBM auth mode");
        flb_ibm_logs_conf_destroy(ctx);
        return -1;
    }

    /* Retrieve access token */
    flb_sds_t token = NULL;
    token = flb_oauth2_token_get(oauth2_ctx);
    ctx->bearer_token = flb_sds_create(token);
    if (!ctx->bearer_token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        flb_ibm_logs_conf_destroy(ctx);
        return -1;
    }

    flb_oauth2_destroy(oauth2_ctx);

    return 0;
}