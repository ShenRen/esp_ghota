#ifndef GITHUB_OTA_H
#define GITHUB_OTA_H

#include <esp_err.h>
#include <esp_event.h>
#include "semver.h"

#ifdef __cplusplus
extern "C" {
#endif

ESP_EVENT_DECLARE_BASE(GHOTA_EVENTS);

/** 
 * @brief Github OTA events
 * These events are posted to the event loop to track progress of the OTA process
 */
typedef enum
{
    GHOTA_EVENT_START_CHECK = 0x01,    /*!< Github OTA check started */
    GHOTA_EVENT_UPDATE_AVAILABLE = 0x02,   /*!< Github OTA update available */
    GHOTA_EVENT_NOUPDATE_AVAILABLE = 0x04, /*!< Github OTA no update available */
    GHOTA_EVENT_START_FIRMWARE_UPDATE = 0x08,  /*!< Github OTA firmware update started */
    GHOTA_EVENT_FINISH_FIRMWARE_UPDATE = 0x10, /*!< Github OTA firmware update finished */
    GHOTA_EVENT_FIRMWARE_UPDATE_FAILED = 0x20, /*!< Github OTA firmware update failed */
    GHOTA_EVENT_START_STORAGE_UPDATE = 0x40, /*!< Github OTA storage update started. If the storage is mounted, you should unmount it when getting this call */
    GHOTA_EVENT_FINISH_STORAGE_UPDATE = 0x80, /*!< Github OTA storage update finished. You can mount the new storage after getting this call if needed */
    GHOTA_EVENT_STORAGE_UPDATE_FAILED = 0x100, /*!< Github OTA storage update failed */
    GHOTA_EVENT_START_FILE_UPDATE = 0x200,  /*!< Github OTA file update started */
    GHOTA_EVENT_FINISH_FILE_UPDATE = 0x400, /*!< Github OTA file update finished */
    GHOTA_EVENT_FILE_UPDATE_FAILED = 0x800, /*!< Github OTA file update failed */
    GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS = 0x1000, /*!< Github OTA firmware update progress */
    GHOTA_EVENT_STORAGE_UPDATE_PROGRESS = 0x2000, /*!< Github OTA storage update progress */
    GHOTA_EVENT_FILE_UPDATE_PROGRESS = 0x4000, /*!< Github OTA file update progress */
    GHOTA_EVENT_PENDING_REBOOT = 0x8000, /*!< Github OTA pending reboot */
} ghota_event_e;

/** 
 * @brief Git hosting platforms or services
 * These events are posted to the event loop to track progress of the OTA process
 */
typedef enum
{
    GHOTA_HOST_CUSTOM = 0x00,
    GHOTA_HOST_GITHUB = 0x01, /*!< GitHub open-source platform*/
    GHOTA_HOST_GITEE = 0x02, /*!< Gitee, Git-based code hosting and R&D collaboration platform*/
} ghota_host_e;

typedef enum
{
    GHOTA_ASSET_FIRMWARE = 0x00, /*!< Firmware asset, Only Zero or One allowed*/
    GHOTA_ASSET_STORAGE = 0x01, /*!< Storage asset， Only Zero or One allowed*/
    GHOTA_ASSET_FILE = 0x02, /*!< File assets，Unlimited num*/
} ghota_asset_e;

struct ghota_config_t;

/** 
 * @brief Format the Git API Url
 * The callback function is used to format the Git API Url
 */
typedef esp_err_t (*ghota_apiurlformat_callback_fn)(char* url_buf, size_t url_size, const struct ghota_config_t * ghota_config);

typedef struct ghota_asset_t {
    ghota_asset_e type;
    char nameformat[CONFIG_MAX_FILENAME_LEN]; /*!< Filename to match against on Github indicating this is a asset file */
    semver_t version; /*!< Version of the asset */
    union {
        char filedirpath[CONFIG_MAX_FILENAME_LEN]; /*!< Directory path for a data file */
        char partitionname[17]; /*!< Name of the storage partition to update */
    };
} ghota_asset_t;

/** 
 * @brief Get Asset Version
 * The callback function is used to determine the version of the asset
 */
typedef esp_err_t (*ghota_getversion_callback_fn)(semver_t* version, const ghota_asset_t * asset, const struct ghota_config_t * ghota_config);


/**
 * @brief Github OTA Configuration
 */
typedef struct ghota_config_t {
    ghota_asset_t * assets; /*!< Assets that need to be updated */
    size_t assetssize; /*!< number of assets*/
    ghota_getversion_callback_fn getversioncb; /*!< Callback function to determine the version of the asset*/
    ghota_host_e githost; /*!< Git hosting platform*/
    char *hostname; /*!< Hostname of the Github server. Defaults to api.github.com*/
    char *onwername; /*!< Name of the Github onwer or organization */
    char *reponame; /*!< Name of the Github repository */
    void * userdata; /*!< User data */
    ghota_apiurlformat_callback_fn apiurlformatcb; /*!< Format of the Git API access url. Defaults to https://%s/repos/%s/%s/releases/latest*/
    uint32_t updateInterval; /*!< Interval in Minutes to check for updates if using the ghota_start_update_timer function */
} ghota_config_t;

typedef struct ghota_client_handle_t ghota_client_handle_t;

/**
 * @brief  Initialize the github ota client
 * 
 * 
 * @param config [in] Configuration for the github ota client
 * @return ghota_client_handle_t* handle to pass to all subsequent calls. If it returns NULL, there is a error in your config
 */
ghota_client_handle_t *ghota_init(ghota_config_t *config);

/**
 * @brief Set the Username and Password to access private repositories or get more API calls
 * 
 * Anonymus API calls are limited to 60 per hour. If you want to get more calls, you need to set a username and password.
 * Be aware that this will be stored in the flash and can be read by anyone with access to the flash.
 * The password should be a Github Personal Access Token and for good security you should limit what it can do
 * 
 * @param handle the handle returned by ghota_init
 * @param username the username to authenticate with
 * @param password this Github Personal Access Token
 * @return esp_err_t ESP_OK if all is good, ESP_FAIL if there is an error
 */
esp_err_t ghota_set_auth(ghota_client_handle_t *handle, const char *username, const char *password);
/**
 * @brief Free the ghota client handle and all resources
 * 
 * @param handle the Handle
 * @return esp_err_t if there was a error
 */
esp_err_t ghota_free(ghota_client_handle_t *handle);

/**
 * @brief Perform a check for updates
 * 
 * This will just check if there is a available update on Github releases with download resources that match your configuration
 * for firmware and storage files. If it returns ESP_OK, you can call ghota_get_latest_version to get the version of the latest release
 * 
 * @param handle the ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if there is a update available, ESP_FAIL if there is no update available or an error
 */
esp_err_t ghota_check(ghota_client_handle_t *handle);

/**
 * @brief Downloads and writes the latest firmware and storage partition (if available)
 * 
 * You should only call this after calling ghota_check and ensuring that there is a update available. 
 * 
 * @param handle the ghota_client_handle_t handle
 * @return esp_err_t ESP_FAIL if there is a error. If the Update is successful, it will not return, but reboot the device
 */
esp_err_t ghota_update(ghota_client_handle_t *handle);

/**
 * @brief Get the currently running version of the firmware
 * 
 * This will return the version of the firmware currently running on your device. 
 * consult semver.h for functions to compare versions
 * 
 * @param handle the ghota_client_handle_t handle
 * @return semver_t the version of the latest release
 */

semver_t *ghota_get_current_version(ghota_client_handle_t *handle);

/**
 * @brief Get the version of the latest release on Github. Only valid after calling ghota_check
 * 
 * @param handle the ghota_client_handle_t handle
 * @return semver_t* the version of the latest release on Github
 */
semver_t *ghota_get_latest_version(ghota_client_handle_t *handle);

/**
 * @brief Start a new Task that will check for updates and update if available
 * 
 * This is equivalent to calling ghota_check and ghota_update if there is a new update available.
 * If no update is available, it will not update the device.
 * 
 * Progress can be monitored by registering for the GHOTA_EVENTS events on the Global Event Loop
 * 
 * @param handle ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if the task was started, ESP_FAIL if there was an error
 */
esp_err_t ghota_start_update_task(ghota_client_handle_t *handle);

/**
 * @brief Install a Timer to automatically check for new updates and update if available
 * 
 * Install a timer that will check for new updates every updateInterval seconds and update if available.
 * 
 * @param handle ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if no error, otherwise ESP_FAIL
 */

esp_err_t ghota_start_update_timer(ghota_client_handle_t *handle);

/**
 * @brief convience function to return a string representation of events emited by this library
 * 
 * @param event the eventid passed to the event handler 
 * @return char* a string representing the event
 */
char *ghota_get_event_str(ghota_event_e event);

/**
 * @brief Check if the latest release is a prerelease
 * @note Only valid after event GHOTA_EVENT_UPDATE_AVAILABLE
 * 
 * @return true if the latest release is a prerelease, false otherwise
 */
bool ghota_is_prerelease(ghota_client_handle_t *handle);

/**
 * @brief Get the tag name of the latest release
 * @note Only valid after event GHOTA_EVENT_UPDATE_AVAILABLE
 * 
 * @return const char* the tag name of the latest release
 */
const char* ghota_get_tag_name(ghota_client_handle_t *handle);

/**
 * @brief Get the name of the latest release
 * @note Only valid after event GHOTA_EVENT_UPDATE_AVAILABLE
 * 
 * @return const char* the name of the latest release
 */
const char* ghota_get_release_name(ghota_client_handle_t *handle);

/**
 * @brief Get the changelog of the latest release
 * @note Only valid after event GHOTA_EVENT_UPDATE_AVAILABLE
 * 
 * @return const char* the changelog of the latest release
 */
const char* ghota_get_change_log(ghota_client_handle_t *handle);

/**
 * @brief Get the release date of the latest release
 * @note Only valid after event GHOTA_EVENT_UPDATE_AVAILABLE
 * 
 * @return const char* the release date of the latest release
 */
const char* ghota_get_release_date(ghota_client_handle_t *handle);


#ifdef __cplusplus
}
#endif

#endif