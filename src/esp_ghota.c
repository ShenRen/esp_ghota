#include <stdlib.h>
#include <fnmatch.h>
#include <libgen.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_http_client.h>
#include <esp_tls.h>
#include <esp_crt_bundle.h>
#include <esp_log.h>
#include <esp_app_format.h>
#include <esp_ota_ops.h>
#include <esp_https_ota.h>
#include <esp_event.h>

#include <sdkconfig.h>
#include "esp_ghota.h"
#include "lwjson.h"

#define GHOTA_HOSTNAME_GITHUB "api.github.com"
#define GHOTA_HOSTNAME_GITEE "gitee.com"

static const char *TAG = "GHOTA";

ESP_EVENT_DEFINE_BASE(GHOTA_EVENTS);

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
#define PRICONTENT_LENGTH PRId64
#else
#define PRICONTENT_LENGTH PRId32
#endif

typedef struct ghota_asset_result_t{
    char name[CONFIG_MAX_FILENAME_LEN];
    char url[CONFIG_MAX_URL_LEN];
    size_t size;
} ghota_asset_result_t;


typedef struct ghota_client_handle_t
{
    ghota_config_t config;
    char *username;
    char *token;
    struct
    {
        char tag_name[CONFIG_MAX_FILENAME_LEN];
        char* release_name;
        char* change_log;
        bool is_prerelease;
        char* release_date;
        uint32_t flags;
        ghota_asset_result_t *assets;
    } result;
    uint32_t result_curr_idx;
    ghota_asset_result_t scratch;
    semver_t current_version;
    semver_t latest_version;
    uint32_t countdown;
    TaskHandle_t task_handle;
    const esp_partition_t *storage_partition;
    FILE * file_handle;
} ghota_client_handle_t;

enum release_flags
{
    GHOTA_RELEASE_GOT_TAG = 0x01, /*!< Version tag for the update */
    GHOTA_RELEASE_GOT_NAME = 0x02, /*!< Tag name the update */
    GHOTA_RELEASE_GOT_LOG = 0x04, /*!< Change log for the update */
    GHOTA_RELEASE_GOT_DATE = 0x08, /*!< Date for the update */
    GHOTA_RELEASE_GOT_PRE = 0x10, /*!< the update is a prerelease version*/
    GHOTA_RELEASE_GOT_FNAME = 0x20,
    GHOTA_RELEASE_GOT_FURL = 0x40,

    GHOTA_RELEASE_GOT_FIRMWARE = 0x100,
    GHOTA_RELEASE_GOT_STORAGE = 0x200,
    GHOTA_RELEASE_GOT_FILE = 0x400,

    GHOTA_RELEASE_GOT_ASSETS = GHOTA_RELEASE_GOT_FIRMWARE | GHOTA_RELEASE_GOT_STORAGE | GHOTA_RELEASE_GOT_FILE,
} release_flags;

SemaphoreHandle_t ghota_lock = NULL;

static void SetFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    handle->result.flags |= flag;
}
static bool GetFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    return handle->result.flags & flag;
}

static void ClearFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    handle->result.flags &= ~flag;
}

// GitHub REST API url format callback
static esp_err_t ghota_apiurlformat_github(char* url_buf, size_t url_size, const struct ghota_config_t * ghota_config)
{
    snprintf(url_buf, url_size, "https://%s/repos/%s/%s/releases/latest", ghota_config->hostname, ghota_config->onwername, ghota_config->reponame);
    return ESP_OK;
}

// Gitee Open API url format callback
static esp_err_t ghota_apiurlformat_gitee(char* url_buf, size_t url_size, const struct ghota_config_t * ghota_config)
{
    snprintf(url_buf, url_size, "https://%s/api/v5/repos/%s/%s/releases/latest", ghota_config->hostname, ghota_config->onwername, ghota_config->reponame);
    return ESP_OK;
}

static esp_err_t ghota_getversion(char* ver_buf, size_t ver_size, const ghota_asset_t * asset, const struct ghota_config_t * ghota_config){
    if(asset->type == GHOTA_ASSET_FIRMWARE){
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
        const esp_app_desc_t *app_desc = esp_app_get_description();
#else
        const esp_app_desc_t *app_desc = esp_ota_get_app_description();
#endif
        strncpy(ver_buf,app_desc->version,ver_size);
        return ESP_OK;
    }

    return ESP_FAIL;
}



ghota_client_handle_t *ghota_init(ghota_config_t *newconfig)
{

    if(!newconfig->assets || !newconfig->assetssize){
        ESP_LOGE(TAG, "No assets is provided.");
        return NULL;
    }

    /* Check all assets */
    size_t firmware_num = 0;
    size_t storage_num = 0;
    size_t file_num = 0;
    for(int i = 0; i < newconfig->assetssize ; i++){
        if(strlen(newconfig->assets[i].namematch) == 0){
            ESP_LOGE(TAG, "Asset[%d] not specify name match.",i);
            return NULL;
        }
        if(newconfig->assets[i].type == GHOTA_ASSET_FIRMWARE){
            firmware_num++;
            if(firmware_num > 1){
                ESP_LOGE(TAG, "Cannot specify multiple firmware asset.");
                return NULL;
            }
        } else if(newconfig->assets[i].type == GHOTA_ASSET_STORAGE){
            storage_num++;
            if(storage_num > 1){
                ESP_LOGE(TAG, "Cannot specify multiple storage asset.");
                return NULL;
            }
            if(strlen(newconfig->assets[i].partitionname) == 0){
                ESP_LOGE(TAG, "Storage asset[%d] not specify partitionname.",i);
                return NULL;
            }
        } else if(newconfig->assets[i].type == GHOTA_ASSET_FILE){
            file_num++;
            if(strlen(newconfig->assets[i].filedirpath) == 0){
                ESP_LOGE(TAG, "File asset[%d] not specify filedirpath.",i);
                return NULL;
            }
        }
    }

    if(newconfig->githost == GHOTA_HOST_CUSTOM && newconfig->apiurlformatcb == NULL)
    {
        ESP_LOGE(TAG, "No apiurlformat callback function is provided.");
        return NULL;
    }

    if(newconfig->githost == GHOTA_HOST_CUSTOM && newconfig->hostname == NULL)
    {
        ESP_LOGE(TAG, "No hostname is provided.");
        return NULL;
    }

    if (!ghota_lock)
    {
        ghota_lock = xSemaphoreCreateMutex();
    }
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return NULL;
    }
    ghota_client_handle_t *handle = malloc(sizeof(ghota_client_handle_t));
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for client handle");
        goto init_err;
    }
    bzero(handle, sizeof(ghota_client_handle_t));

    handle->config.assets = newconfig->assets;
    handle->config.assetssize = newconfig->assetssize;

    handle->result.assets = malloc(sizeof(ghota_asset_result_t) * handle->config.assetssize);
    if (handle->result.assets == NULL){
        ESP_LOGE(TAG, "Failed to allocate memory for assets result");
        goto init_err;
    }
    bzero(handle->result.assets, sizeof(ghota_asset_result_t) * handle->config.assetssize);

    if(newconfig->getversioncb == NULL){
        handle->config.getversioncb = ghota_getversion;
    } else {
        handle->config.getversioncb = newconfig->getversioncb;
    }
    
    if(newconfig->githost == GHOTA_HOST_CUSTOM){
        //Try matching git host platform by hostname
        if(newconfig->hostname && strcasecmp(newconfig->hostname,GHOTA_HOSTNAME_GITHUB) == 0){
            handle->config.githost = GHOTA_HOST_GITHUB;
        } else if(newconfig->hostname && strcasecmp(newconfig->hostname,GHOTA_HOSTNAME_GITEE) == 0){
            handle->config.githost = GHOTA_HOST_GITEE;
        } else {
            handle->config.githost = GHOTA_HOST_CUSTOM;
        }
    } else {
        handle->config.githost = newconfig->githost;
    }
    
    if (newconfig->hostname == NULL){
        // Determine host
        if(handle->config.githost == GHOTA_HOST_GITHUB){
            asprintf(&handle->config.hostname, GHOTA_HOSTNAME_GITHUB);
        } else if(handle->config.githost == GHOTA_HOST_GITEE){
            asprintf(&handle->config.hostname, GHOTA_HOSTNAME_GITEE);
        } else {
            asprintf(&handle->config.hostname, CONFIG_GITHUB_HOSTNAME);
        }
    } else
        asprintf(&handle->config.hostname, newconfig->hostname);

    if (newconfig->onwername == NULL)
        asprintf(&handle->config.onwername, CONFIG_GITHUB_OWNER);
    else
        asprintf(&handle->config.onwername, newconfig->onwername);

    if (newconfig->reponame == NULL)
        asprintf(&handle->config.reponame, CONFIG_GITHUB_REPO);
    else
        asprintf(&handle->config.reponame, newconfig->reponame);

    if (newconfig->userdata == NULL)
        handle->config.userdata = NULL;
    else
        handle->config.userdata = newconfig->userdata;

    if (newconfig->apiurlformatcb == NULL){
        // Check host platforms
        if(handle->config.githost == GHOTA_HOST_GITHUB){
            handle->config.apiurlformatcb = ghota_apiurlformat_github;
        } else if(handle->config.githost == GHOTA_HOST_GITEE){
            handle->config.apiurlformatcb = ghota_apiurlformat_gitee;
        } else {
            ESP_LOGE(TAG, "Failed to parse current version");
            goto init_err;
        }
    }
    else
        handle->config.apiurlformatcb = newconfig->apiurlformatcb;

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    const esp_app_desc_t *app_desc = esp_app_get_description();
#else
    const esp_app_desc_t *app_desc = esp_ota_get_app_description();
#endif
    if (semver_parse(app_desc->version, &handle->current_version))
    {
        ESP_LOGE(TAG, "Failed to parse current version");
        goto init_err;
    }
    handle->result.flags = 0;

    //    if (newconfig->updateInterval < 60) {
    //        ESP_LOGE(TAG, "Update interval must be at least 60 Minutes");
    //        newconfig->updateInterval = 60;
    //    }
    handle->config.updateInterval = newconfig->updateInterval;

    handle->task_handle = NULL;
    xSemaphoreGive(ghota_lock);

    return handle;

init_err:
    xSemaphoreGive(ghota_lock);
    ghota_free(handle);
    return NULL;
}

esp_err_t ghota_free(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }

    if (handle->result.assets)
            free(handle->result.assets);
    free(handle->config.hostname);
    free(handle->config.onwername);
    free(handle->config.reponame);
    if (handle->username)
        free(handle->username);
    if (handle->token)
        free(handle->token);
    semver_free(&handle->current_version);
    semver_free(&handle->latest_version);

    // if (handle->result.tag_name)
    //     free(handle->result.tag_name);
    if (handle->result.release_name)
        free(handle->result.release_name);
    if (handle->result.change_log)
        free(handle->result.change_log);
    if (handle->result.release_date)
        free(handle->result.release_date);

    xSemaphoreGive(ghota_lock);
    vSemaphoreDelete(ghota_lock);

    free(handle);
    return ESP_OK;
}

esp_err_t ghota_set_auth(ghota_client_handle_t *handle, const char *username, const char *password)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    asprintf(&handle->username, "%s", username);
    asprintf(&handle->token, "%s", password);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

/**
 * @brief Get the value of a key from the json stream
 * @note The caller is responsible for value_ptr memory release
 * 
 * @param value_ptr Pointer to the value buffer
 * @param buf_size Size of the value buffer
 * @param key Key to search for
 * @param stack_pos Stack position to start searching from
 */
static esp_err_t lwjson_get_key_value(char** value_buf, const size_t buf_size, const char* key, size_t stack_pos, lwjson_stream_parser_t *jsp, lwjson_stream_type_t type){
    ghota_client_handle_t *handle = (ghota_client_handle_t *)jsp->udata;

    if (jsp->stack_pos >= stack_pos                        /* Number of stack entries must be high */
        && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT /* First must be object */
        && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY    /* We need key to be before */
        && strcasecmp(jsp->stack[1].meta.name, key) == 0)
    {
        ESP_LOGI(TAG, "Got key '%s' with value '%s'", jsp->stack[1].meta.name, jsp->data.str.buff);
        if(*value_buf){
            strncpy(*value_buf, jsp->data.str.buff, buf_size);
        }else{
            char * value_tmp = NULL;
            asprintf(&value_tmp, jsp->data.str.buff);
            if(!value_tmp){
                ESP_LOGI(TAG, "No memory for key '%s' with value '%s'",jsp->stack[1].meta.name, jsp->data.str.buff);
                return ESP_ERR_NO_MEM;
            }
            *value_buf = value_tmp;
        }
        return ESP_OK;
    }
    return ESP_FAIL;
} 

static esp_err_t lwjson_get_bool_value(bool* value_ptr, const char* key, size_t stack_pos, lwjson_stream_parser_t *jsp, lwjson_stream_type_t type){
    ghota_client_handle_t *handle = (ghota_client_handle_t *)jsp->udata;
    if (jsp->stack_pos >= stack_pos                        /* Number of stack entries must be high */
        && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT /* First must be object */
        && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY    /* We need key to be before */
        && strcasecmp(jsp->stack[1].meta.name, key) == 0)
    {
        *value_ptr = strcasecmp(jsp->data.str.buff, "true") == 0;
        ESP_LOGI(TAG, "Got bool '%s' with value '%s'", jsp->stack[1].meta.name, jsp->data.str.buff);
        return ESP_OK;
    }
    return ESP_FAIL;
} 

static void _lwjson_laste_callback(lwjson_stream_parser_t *jsp, lwjson_stream_type_t type)
{
    if (jsp->udata == NULL)
    {
        ESP_LOGE(TAG, "No user data for callback");
        return;
    }
    ghota_client_handle_t *handle = (ghota_client_handle_t *)jsp->udata;
#ifdef DEBUG
    ESP_LOGD(TAG, "Lwjson Called: %d %d %d %d", jsp->stack_pos, jsp->stack[jsp->stack_pos - 1].type, type, handle->result.flags);
    if (jsp->stack[jsp->stack_pos - 1].type == LWJSON_STREAM_TYPE_KEY)
    { /* We need key to be before */
        ESP_LOGD(TAG, "Key: %s", jsp->stack[jsp->stack_pos - 1].meta.name);
    }
#endif

    /* Get a value corresponsing to "tag_name" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_TAG)){
        char* name = handle->result.tag_name;
        if(lwjson_get_key_value(&name, sizeof(handle->result.tag_name), "tag_name", 2, jsp, type) == ESP_OK){
            SetFlag(handle, GHOTA_RELEASE_GOT_TAG);
        }
    }
    /* Get a value corresponsing to "name" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_NAME)){
        if(lwjson_get_key_value(&handle->result.release_name, 0, "name", 2, jsp, type) == ESP_OK){
            SetFlag(handle, GHOTA_RELEASE_GOT_NAME);
        }
    }
    /* Get a value corresponsing to "body" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_LOG)){
        if(lwjson_get_key_value(&handle->result.change_log, 0, "body", 2, jsp, type) == ESP_OK){
            SetFlag(handle, GHOTA_RELEASE_GOT_LOG);
        }
    }
    /* Get a value corresponsing to "created_at" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_DATE)){
        if(lwjson_get_key_value(&handle->result.release_date, 0, "created_at", 2, jsp, type) == ESP_OK){
            SetFlag(handle, GHOTA_RELEASE_GOT_DATE);
        }
    }
    /* Get a value corresponsing to "prerelease" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_PRE)){
        if(lwjson_get_bool_value(&handle->result.is_prerelease, "prerelease", 2, jsp, type) == ESP_OK){
            SetFlag(handle, GHOTA_RELEASE_GOT_PRE);
        }
    }

    if (jsp->stack_pos == 5 
        && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT 
        && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY 
        && strcasecmp(jsp->stack[1].meta.name, "assets") == 0 
        && jsp->stack[2].type == LWJSON_STREAM_TYPE_ARRAY 
        && jsp->stack[3].type == LWJSON_STREAM_TYPE_OBJECT 
        && jsp->stack[4].type == LWJSON_STREAM_TYPE_KEY)
    {
        ESP_LOGD(TAG, "Assets Got key '%s' with value '%s'", jsp->stack[jsp->stack_pos - 1].meta.name, jsp->data.str.buff);
        /* Get Asset Name */
        if (strcasecmp(jsp->stack[4].meta.name, "name") == 0)
        {
            strncpy(handle->scratch.name, jsp->data.str.buff, CONFIG_MAX_FILENAME_LEN);
            SetFlag(handle, GHOTA_RELEASE_GOT_FNAME);
            ESP_LOGI(TAG, "Got Filename for Asset: %s", handle->scratch.name);
        }
        /* Get Asset Download url */
        if (strcasecmp(jsp->stack[4].meta.name, "browser_download_url") == 0)
        {
            strncpy(handle->scratch.url, jsp->data.str.buff, CONFIG_MAX_URL_LEN);
            SetFlag(handle, GHOTA_RELEASE_GOT_FURL);
            ESP_LOGI(TAG, "Got URL for Asset: %s", handle->scratch.url);
        }
        /* Now test if we got both name an download url */
        if (GetFlag(handle, GHOTA_RELEASE_GOT_FNAME) && GetFlag(handle, GHOTA_RELEASE_GOT_FURL))
        {
            ghota_asset_t * asset;
            ghota_asset_result_t * result;
            ghota_asset_result_t * scratch = &handle->scratch;
            bool asset_find = false;
            
            for(int i = 0;i < handle->config.assetssize; i++)
            {
                asset = &handle->config.assets[i];
                result = &handle->result.assets[i];

                ESP_LOGD(TAG, "Testing Asset filenames %s  - Matching Filename %s", handle->scratch.name, asset->namematch);

                /* see if the filename matches firmware name*/
                if (!GetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE) && asset->type == GHOTA_ASSET_FIRMWARE 
                    && fnmatch(asset->namematch, scratch->name, 0) == 0)
                {
                    strncpy(result->name, scratch->name, CONFIG_MAX_FILENAME_LEN);
                    strncpy(result->url, scratch->url, CONFIG_MAX_URL_LEN);
                    ESP_LOGI(TAG, "Valid Firmware Asset Found: %s - %s", result->name, result->url);
                    SetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE);
                    asset_find = true;
                    break;
                }
                /* see if the filename matches storage name*/
                else if (!GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE) && asset->type == GHOTA_ASSET_STORAGE 
                    && fnmatch(asset->namematch, scratch->name, 0) == 0)
                {
                    strncpy(result->name, scratch->name, CONFIG_MAX_FILENAME_LEN);
                    strncpy(result->url, scratch->url, CONFIG_MAX_URL_LEN);
                    ESP_LOGI(TAG, "Valid Storage Asset Found: %s - %s", result->name, result->url);
                    SetFlag(handle, GHOTA_RELEASE_GOT_STORAGE);
                    asset_find = true;
                    break;
                }
                /* see if the filename matches file name*/
                else if(fnmatch(asset->namematch, scratch->name, 0) == 0)
                {
                    strncpy(result->name, scratch->name, CONFIG_MAX_FILENAME_LEN);
                    strncpy(result->url, scratch->url, CONFIG_MAX_URL_LEN);
                    ESP_LOGI(TAG, "Valid File Asset Found: %s - %s", result->name, result->url);
                    SetFlag(handle, GHOTA_RELEASE_GOT_FILE);
                    asset_find = true;
                    break;
                }
            }
            
            if(!asset_find)
            {
                ESP_LOGD(TAG, "Invalid Asset Found: %s", handle->scratch.name);
            }
            handle->scratch.name[0] = '\0';
            handle->scratch.url[0] = '\0';
            ClearFlag(handle, GHOTA_RELEASE_GOT_FNAME);
            ClearFlag(handle, GHOTA_RELEASE_GOT_FURL);
        }
    }
}

static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    lwjsonr_t res;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_HEADER:
        if (strncasecmp(evt->header_key, "x-ratelimit-remaining", strlen("x-ratelimit-remaining")) == 0)
        {
            int limit = atoi(evt->header_value);
            ESP_LOGD(TAG, "Github API Rate Limit Remaining: %d", limit);
            if (limit < 10)
            {
                ESP_LOGW(TAG, "Github API Rate Limit Remaining is low: %d", limit);
            }
        }
        break;
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            char *buf = evt->data;
            for (int i = 0; i < evt->data_len; i++)
            {
                res = lwjson_stream_parse((lwjson_stream_parser_t *)evt->user_data, *buf);
                if (!(res == lwjsonOK || res == lwjsonSTREAMDONE || res == lwjsonSTREAMINPROG))
                {
                    ESP_LOGE(TAG, "Lwjson Error: %d", res);
                }
                buf++;
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED:
    {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        break;
    }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_check(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to get lock");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Checking for new release");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_CHECK, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
    lwjson_stream_parser_t stream_parser;
    lwjsonr_t res;

    res = lwjson_stream_init(&stream_parser, _lwjson_laste_callback);
    if (res != lwjsonOK)
    {
        ESP_LOGE(TAG, "Failed to initialize JSON parser: %d", res);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    stream_parser.udata = (void *)handle;

    char url[CONFIG_MAX_URL_LEN];
    esp_err_t err = handle->config.apiurlformatcb(url, CONFIG_MAX_URL_LEN, &handle->config);
    if (err == ESP_OK && strlen(url) > 0 )
    {
        ESP_LOGD(TAG, "Succeed to format git api url = %s", url);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to format git api url: %s", esp_err_to_name(err));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    esp_http_client_config_t httpconfig = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = _http_event_handler,
        .user_data = &stream_parser,
    };
    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }
    ESP_LOGI(TAG, "Searching for Assets from %s", url);

    esp_http_client_handle_t client = esp_http_client_init(&httpconfig);

    err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRICONTENT_LENGTH ,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    if (esp_http_client_get_status_code(client) == 200)
    {
        if (GetFlag(handle, GHOTA_RELEASE_GOT_ASSETS))
        {
            if (semver_parse(handle->result.tag_name, &handle->latest_version))
            {
                ESP_LOGE(TAG, "Failed to parse new version");
                esp_http_client_cleanup(client);
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
                xSemaphoreGive(ghota_lock);
                return ESP_FAIL;
            }
            ESP_LOGI(TAG, "Current Version %d.%d.%d", handle->current_version.major, handle->current_version.minor, handle->current_version.patch);
            ESP_LOGI(TAG, "New Version %d.%d.%d", handle->latest_version.major, handle->latest_version.minor, handle->latest_version.patch);

            for(int i = 0; i < handle->config.assetssize; i++)
            {
                if (strlen(handle->result.assets[i].url))
                {
                    if(handle->config.assets[i].type == GHOTA_ASSET_FIRMWARE){
                        ESP_LOGI(TAG, "Firmware NAME: %s", handle->result.assets[i].name);
                        ESP_LOGI(TAG, "Firmware URL: %s", handle->result.assets[i].url);
                    } else if(handle->config.assets[i].type == GHOTA_ASSET_STORAGE){
                        ESP_LOGI(TAG, "Storage NAME: %s", handle->result.assets[i].name);
                        ESP_LOGI(TAG, "Storage URL: %s", handle->result.assets[i].url);
                    } else if(handle->config.assets[i].type == GHOTA_ASSET_FILE){
                        ESP_LOGI(TAG, "File NAME: %s", handle->result.assets[i].name);
                        ESP_LOGI(TAG, "File URL: %s", handle->result.assets[i].url);
                    }
                }
            }
        }
        else
        {
            ESP_LOGI(TAG, "Asset: No Valid Assets Found ");
            esp_http_client_cleanup(client);
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
            xSemaphoreGive(ghota_lock);
            return ESP_FAIL;
        }
    }
    else
    {
        ESP_LOGW(TAG, "Github Release API Returned: %d", esp_http_client_get_status_code(client));
        esp_http_client_cleanup(client);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    esp_http_client_cleanup(client);
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

static esp_err_t validate_image_header(esp_app_desc_t *new_app_info)
{
    if (new_app_info == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "New Firmware Details:");
    ESP_LOGI(TAG, "Project name: %s", new_app_info->project_name);
    ESP_LOGI(TAG, "Firmware version: %s", new_app_info->version);
    ESP_LOGI(TAG, "Compiled time: %s %s", new_app_info->date, new_app_info->time);
    ESP_LOGI(TAG, "ESP-IDF: %s", new_app_info->idf_ver);
    ESP_LOGI(TAG, "SHA256:");
    ESP_LOG_BUFFER_HEX(TAG, new_app_info->app_elf_sha256, sizeof(new_app_info->app_elf_sha256));

    const esp_partition_t *running = esp_ota_get_running_partition();
    ESP_LOGD(TAG, "Current partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             running->label, running->type, running->subtype, running->address);
    const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);
    ESP_LOGD(TAG, "Update partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             update->label, update->type, update->subtype, update->address);

#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    /**
     * Secure version check from firmware image header prevents subsequent download and flash write of
     * entire firmware image. However this is optional because it is also taken care in API
     * esp_https_ota_finish at the end of OTA update procedure.
     */
    const uint32_t hw_sec_version = esp_efuse_read_secure_version();
    if (new_app_info->secure_version < hw_sec_version)
    {
        ESP_LOGW(TAG, "New firmware security version is less than eFuse programmed, %d < %d", new_app_info->secure_version, hw_sec_version);
        return ESP_FAIL;
    }
#endif

    return ESP_OK;
}

static esp_err_t http_client_set_header_cb(esp_http_client_handle_t http_client)
{
    return esp_http_client_set_header(http_client, "Accept", "application/octet-stream");
}

esp_err_t _http_event_storage_handler(esp_http_client_event_t *evt)
{
    static int output_pos;
    static int last_progress;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_CONNECTED:
    {
        output_pos = 0;
        last_progress = 0;
        /* Erase the Partition */
        break;
    }
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            ghota_client_handle_t *handle = (ghota_client_handle_t *)evt->user_data;
            if (output_pos == 0)
            {
                handle->result.assets[handle->result_curr_idx].size = esp_http_client_get_content_length(evt->client);
                ESP_LOGI(TAG, "Storage asset Size %d", (int)handle->result.assets[handle->result_curr_idx].size);

                ESP_LOGD(TAG, "Erasing Partition");
                ESP_ERROR_CHECK(esp_partition_erase_range(handle->storage_partition, 0, handle->storage_partition->size));
                ESP_LOGD(TAG, "Erasing Complete");
            }

            ESP_ERROR_CHECK(esp_partition_write(handle->storage_partition, output_pos, evt->data, evt->data_len));
            output_pos += evt->data_len;
            int progress = 100 * ((float)output_pos / (float)handle->result.assets[handle->result_curr_idx].size);
            if ((progress % 5 == 0) && (progress != last_progress))
            {
                ESP_LOGV(TAG, "Storage Firmware Update Progress: %d%%", progress);
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
                last_progress = progress;
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED:
    {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        break;
    }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t _http_event_file_handler(esp_http_client_event_t *evt)
{
    static int output_pos;
    static int last_progress;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_CONNECTED:
    {
        output_pos = 0;
        last_progress = 0;
        /* Erase the Partition */
        break;
    }
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            ghota_client_handle_t *handle = (ghota_client_handle_t *)evt->user_data;
            if (output_pos == 0)
            {
                handle->result.assets[handle->result_curr_idx].size = esp_http_client_get_content_length(evt->client);
                ESP_LOGI(TAG, "File[%d] asset Size %d", (int)handle->result_curr_idx,(int)handle->result.assets[handle->result_curr_idx].size);
            }
            if(ftell(handle->file_handle) != output_pos){
                fseek(handle->file_handle,output_pos,SEEK_SET);
            }

            size_t write_obj_size = fwrite(evt->data, evt->data_len, 1, handle->file_handle);
            if(write_obj_size != 1){
                ESP_LOGE(TAG, "An error(%d) occurred writing the file, data(%d) writen(%d)", ferror(handle->file_handle), 1, write_obj_size);
                return ESP_FAIL;
            }
            output_pos += evt->data_len;
            // FIXME: 如何知道文件大小
            int progress = 100 * ((float)output_pos / (float)handle->result.assets[handle->result_curr_idx].size);
            if ((progress % 5 == 0) && (progress != last_progress))
            {
                ESP_LOGV(TAG, "File Firmware Update Progress: %d%%", progress);
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FILE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
                last_progress = progress;
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED:
    {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        break;
    }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_firmware_update(ghota_client_handle_t *handle, uint32_t asset_idx){

    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Invalid Handle");
        xSemaphoreGive(ghota_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (!strlen(handle->result.assets[asset_idx].url))
    {
        ESP_LOGE(TAG, "No Firmware URL");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    esp_err_t ota_finish_err = ESP_OK;
    
    esp_http_client_config_t httpconfig = {
        .url = handle->result.assets[asset_idx].url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
        .buffer_size_tx = 4096,
    };

    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", httpconfig.url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }

    esp_https_ota_config_t ota_config = {
        .http_config = &httpconfig,
        .http_client_init_cb = http_client_set_header_cb,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ESP HTTPS OTA Begin failed: %d", err);
        goto fw_ota_end;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_https_ota_read_img_desc failed: %d", err);
        goto fw_ota_end;
    }
    err = validate_image_header(&app_desc);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "image header verification failed: %d", err);
        goto fw_ota_end;
    }
    int last_progress = -1;
    while (1)
    {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
        {
            break;
        }
        int32_t dl = esp_https_ota_get_image_len_read(https_ota_handle);
        int32_t size = esp_https_ota_get_image_size(https_ota_handle);
        int progress = 100 * ((float)dl / (float)size);
        if ((progress % 5 == 0) && (progress != last_progress))
        {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
            ESP_LOGV(TAG, "Firmware Update Progress: %d%%", progress);
            last_progress = progress;
        }
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true)
    {
        // the OTA image was not completely received and user can customise the response to this situation.
        ESP_LOGE(TAG, "Complete data was not received.");
    }
    else
    {
        ota_finish_err = esp_https_ota_finish(https_ota_handle);
        if ((err == ESP_OK) && (ota_finish_err == ESP_OK))
        {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_FIRMWARE_UPDATE, NULL, 0, portMAX_DELAY));
            /* give time for the system to react, such as unmounting the filesystems etc */
            vTaskDelay(pdMS_TO_TICKS(1000));
            xSemaphoreGive(ghota_lock);
            return ESP_OK;
        }
        else
        {
            if (ota_finish_err == ESP_ERR_OTA_VALIDATE_FAILED)
            {
                ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            }
            ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed 0x%x", ota_finish_err);
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
            xSemaphoreGive(ghota_lock);
            return ESP_FAIL;
        }
    }

fw_ota_end:
    esp_https_ota_abort(https_ota_handle);
    ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    xSemaphoreGive(ghota_lock);
    return ESP_FAIL;
}

esp_err_t ghota_storage_update(ghota_client_handle_t *handle, uint32_t asset_idx)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Invalid Handle");
        xSemaphoreGive(ghota_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (!strlen(handle->result.assets[asset_idx].url))
    {
        ESP_LOGE(TAG, "No Storage URL");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    if (!strlen(handle->config.assets[asset_idx].partitionname))
    {
        ESP_LOGE(TAG, "No Storage Partition Name");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    handle->storage_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, handle->config.assets[asset_idx].partitionname);
    if (handle->storage_partition == NULL)
    {
        ESP_LOGE(TAG, "Storage Partition %s Not Found",handle->config.assets[asset_idx].partitionname);
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "Storage Partition %s - Type %x Subtype %x Found at %" PRIx32 " - size %" PRIu32, handle->storage_partition->label, handle->storage_partition->type, handle->storage_partition->subtype, handle->storage_partition->address, handle->storage_partition->size);
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
    /* give time for the system to react, such as unmounting the filesystems etc */
    vTaskDelay(pdMS_TO_TICKS(1000));

    esp_http_client_config_t config = {
        .url = handle->result.assets[asset_idx].url,
        .event_handler = _http_event_storage_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_data = handle,
        .buffer_size_tx = 2048,

    };
    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", config.url);
        config.username = handle->username;
        config.password = handle->token;
        config.auth_type = HTTP_AUTH_TYPE_BASIC;
    }
    esp_http_client_handle_t client = esp_http_client_init(&config);
    ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/octet-stream"));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {   
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRICONTENT_LENGTH ,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
        uint8_t sha256[32] = {0};
        ESP_ERROR_CHECK(esp_partition_get_sha256(handle->storage_partition, sha256));
        ESP_LOG_BUFFER_HEX("New Storage Partition SHA256:", sha256, sizeof(sha256));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
        /* give time for the system to react, such as unmounting the filesystems etc */
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    }
    esp_http_client_cleanup(client);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

esp_err_t ghota_file_update(ghota_client_handle_t *handle, uint32_t asset_idx)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Invalid Handle");
        xSemaphoreGive(ghota_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (!strlen(handle->result.assets[asset_idx].url))
    {
        ESP_LOGE(TAG, "No File URL");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    if (!strlen(handle->config.assets[asset_idx].filedirpath))
    {
        ESP_LOGE(TAG, "No File dir path");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    // Create/open asset file
    char file_name[CONFIG_MAX_FILENAME_LEN];
    snprintf(file_name,CONFIG_MAX_FILENAME_LEN,"%s/%s", handle->config.assets[asset_idx].filedirpath ,handle->result.assets[asset_idx].name);
    handle->file_handle = fopen(file_name, "w");
    if (handle->file_handle == NULL) {
        ESP_LOGE(TAG, "Failed to open/create asset file:%s", file_name); // TODO: 打开文件出错
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FILE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_FILE_UPDATE, NULL, 0, portMAX_DELAY));
    /* give time for the system to react, such as close the file etc */
    vTaskDelay(pdMS_TO_TICKS(1000));

    esp_http_client_config_t config = {
        .url = handle->result.assets[asset_idx].url,
        .event_handler = _http_event_file_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_data = handle,
        .buffer_size_tx = 2048,

    };
    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", config.url);
        config.username = handle->username;
        config.password = handle->token;
        config.auth_type = HTTP_AUTH_TYPE_BASIC;
    }
    esp_http_client_handle_t client = esp_http_client_init(&config);
    ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/octet-stream"));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRICONTENT_LENGTH ,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));

        // TODO: 检查文件大小
        //uint8_t sha256[32] = {0};
        // ESP_ERROR_CHECK(esp_partition_get_sha256(handle->storage_partition, sha256));
        // ESP_LOG_BUFFER_HEX("New Storage Partition SHA256:", sha256, sizeof(sha256));

        // Close asset file
        fclose(handle->file_handle);
        handle->file_handle = NULL;
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_FILE_UPDATE, NULL, 0, portMAX_DELAY));
        /* give time for the system to react, such as unmounting the filesystems etc */
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    else
    {   
        // delete asset file
        fclose(handle->file_handle);
        handle->file_handle = NULL;
        remove(file_name);
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FILE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    }
    esp_http_client_cleanup(client);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

esp_err_t ghota_update(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Scheduled Check for Firmware Update Starting");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_FIRMWARE_UPDATE, NULL, 0, portMAX_DELAY));
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE) && !GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE))
    {
        ESP_LOGE(TAG, "No Valid Release Asset Found");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    int cmp = semver_compare_version(handle->latest_version, handle->current_version);
    if (cmp != 1)
    {
        ESP_LOGE(TAG, "Current Version is equal or newer than new release");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_OK;
    }
    xSemaphoreGive(ghota_lock);

    esp_err_t firmware_err = ESP_FAIL;
    esp_err_t storage_err = ESP_FAIL;

    for(int i = 0; i < handle->config.assetssize; i++){
        ghota_asset_t * asset = &handle->config.assets[i];
        ghota_asset_result_t * result = &handle->result.assets[i];
        handle->result_curr_idx = i;
        ESP_LOGI(TAG, "Update asset[%d], %s",i,result->name);
        if (asset->type == GHOTA_ASSET_FIRMWARE && GetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE) && strlen(result->url)){
            firmware_err = ghota_firmware_update(handle,i);
            if (firmware_err == ESP_OK){
                ESP_LOGI(TAG, "Firmware Update Successful");
            } else {
                ESP_LOGE(TAG, "Firmware Update Failed");
            }
        } else if (asset->type == GHOTA_ASSET_STORAGE && GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE) && strlen(result->url)){
            storage_err = ghota_storage_update(handle,i);
            if (storage_err == ESP_OK){
                ESP_LOGI(TAG, "Storage [%s] Update Successful",asset->partitionname);
            } else {
                ESP_LOGE(TAG, "Storage [%s] Update Failed",asset->partitionname);
            }
        } else if (asset->type == GHOTA_ASSET_FILE && GetFlag(handle, GHOTA_RELEASE_GOT_FILE) && strlen(result->url)){
            storage_err = ghota_file_update(handle,i);
            if (storage_err == ESP_OK){
                ESP_LOGI(TAG, "File Update Successful: %s", result->name);
            } else {
                ESP_LOGE(TAG, "File Update Failed: %s", result->name);
            }
        }
    }

    // TODO: Check whether the system need restarts
    if((GetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE) && firmware_err == ESP_OK) 
        || (GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE) && storage_err == ESP_OK)){
        ESP_LOGI(TAG, "Ghota upgrade successful. Rebooting ...");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_PENDING_REBOOT, NULL, 0, portMAX_DELAY));
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_restart();
    }

    return ESP_OK;
}

semver_t *ghota_get_current_version(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return NULL;
    }
    semver_t *cur = malloc(sizeof(semver_t));
    memcpy(cur, &handle->current_version, sizeof(semver_t));
    return cur;
}

semver_t *ghota_get_latest_version(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return NULL;
    }
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_FIRMWARE) && !GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE))
    {
        return NULL;
    }
    semver_t *new = malloc(sizeof(semver_t));
    memcpy(new, &handle->latest_version, sizeof(semver_t));
    return new;
}

static void ghota_task(void *pvParameters)
{
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvParameters;
    ESP_LOGI(TAG, "Firmware Update Task Starting");
    if (handle)
    {
        if (ghota_check(handle) == ESP_OK)
        {
            if (semver_gt(handle->latest_version, handle->current_version) == 1)
            {
                ESP_LOGI(TAG, "New Version Available");
                ghota_update(handle);
            }
            else
            {
                ESP_LOGI(TAG, "No New Version Available");
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, NULL, 0, portMAX_DELAY));
            }
        }
        else
        {
            ESP_LOGI(TAG, "No Update Available");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, NULL, 0, portMAX_DELAY));
        }
    }
    ESP_LOGI(TAG, "Firmware Update Task Finished");
    vTaskDelete(handle->task_handle);
    vTaskDelay(pdMS_TO_TICKS(1000));
    handle->task_handle = NULL;
}

esp_err_t ghota_start_update_task(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return ESP_FAIL;
    }
    eTaskState state = eInvalid;
    TaskHandle_t tmp = xTaskGetHandle("ghota_task");
    if (tmp)
    {
        state = eTaskGetState(tmp);
    }
    if (state == eDeleted || state == eInvalid)
    {
        ESP_LOGD(TAG, "Starting Task to Check for Updates");
        if (xTaskCreate(ghota_task, "ghota_task", 6144, handle, 5, &handle->task_handle) != pdPASS)
        {
            ESP_LOGW(TAG, "Failed to Start ghota_task");
            return ESP_FAIL;
        }
    }
    else
    {
        ESP_LOGW(TAG, "ghota_task Already Running");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void ghota_timer_callback(TimerHandle_t xTimer)
{
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvTimerGetTimerID(xTimer);
    if (handle)
    {
        handle->countdown--;
        if (handle->countdown == 0)
        {
            handle->countdown = handle->config.updateInterval;
            ghota_start_update_task(handle);
        }
    }
}

esp_err_t ghota_start_update_timer(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        ESP_LOGE(TAG, "Failed to initialize GHOTA Client");
        return ESP_FAIL;
    }
    handle->countdown = handle->config.updateInterval;

    /* run timer every minute */
    uint64_t ticks = pdMS_TO_TICKS(1000) * 60;
    TimerHandle_t timer = xTimerCreate("ghota_timer", ticks, pdTRUE, (void *)handle, ghota_timer_callback);
    if (timer == NULL)
    {
        ESP_LOGE(TAG, "Failed to create timer");
        return ESP_FAIL;
    }
    else
    {
        if (xTimerStart(timer, 0) != pdPASS)
        {
            ESP_LOGE(TAG, "Failed to start timer");
            return ESP_FAIL;
        }
        else
        {
            ESP_LOGI(TAG, "Started Update Timer for %" PRIu32 " Minutes", handle->config.updateInterval);
        }
    }
    return ESP_OK;
}

char *ghota_get_event_str(ghota_event_e event)
{
    switch (event)
    {
    case GHOTA_EVENT_START_CHECK:
        return "GHOTA_EVENT_START_CHECK";
    case GHOTA_EVENT_UPDATE_AVAILABLE:
        return "GHOTA_EVENT_UPDATE_AVAILABLE";
    case GHOTA_EVENT_NOUPDATE_AVAILABLE:
        return "GHOTA_EVENT_NOUPDATE_AVAILABLE";
    case GHOTA_EVENT_START_FIRMWARE_UPDATE:
        return "GHOTA_EVENT_START_FIRMWARE_UPDATE";
    case GHOTA_EVENT_FINISH_FIRMWARE_UPDATE:
        return "GHOTA_EVENT_FINISH_FIRMWARE_UPDATE";
    case GHOTA_EVENT_FIRMWARE_UPDATE_FAILED:
        return "GHOTA_EVENT_FIRMWARE_UPDATE_FAILED";
    case GHOTA_EVENT_START_STORAGE_UPDATE:
        return "GHOTA_EVENT_START_STORAGE_UPDATE";
    case GHOTA_EVENT_FINISH_STORAGE_UPDATE:
        return "GHOTA_EVENT_FINISH_STORAGE_UPDATE";
    case GHOTA_EVENT_STORAGE_UPDATE_FAILED:
        return "GHOTA_EVENT_STORAGE_UPDATE_FAILED";
    case GHOTA_EVENT_START_FILE_UPDATE:
        return "GHOTA_EVENT_START_FILE_UPDATE";
    case GHOTA_EVENT_FINISH_FILE_UPDATE:
        return "GHOTA_EVENT_FINISH_FILE_UPDATE";
    case GHOTA_EVENT_FILE_UPDATE_FAILED:
        return "GHOTA_EVENT_FILE_UPDATE_FAILED";
    case GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS:
        return "GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS";
    case GHOTA_EVENT_STORAGE_UPDATE_PROGRESS:
        return "GHOTA_EVENT_STORAGE_UPDATE_PROGRESS";
    case GHOTA_EVENT_FILE_UPDATE_PROGRESS:
        return "GHOTA_EVENT_FILE_UPDATE_PROGRESS";
    case GHOTA_EVENT_PENDING_REBOOT:
        return "GHOTA_EVENT_PENDING_REBOOT";
    }
    return "Unknown Event";
}

bool ghota_is_prerelease(ghota_client_handle_t *handle){
    return handle->result.is_prerelease;
}

const char* ghota_get_tag_name(ghota_client_handle_t *handle){
    return handle->result.tag_name;
}

const char* ghota_get_release_name(ghota_client_handle_t *handle){
    return handle->result.release_name;
}

const char* ghota_get_change_log(ghota_client_handle_t *handle){
    return handle->result.change_log;
}

const char* ghota_get_release_date(ghota_client_handle_t *handle){
    return handle->result.release_date;
}