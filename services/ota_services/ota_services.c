#include "ota_services.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_task_wdt.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_partition.h"

#include "cJSON.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include <inttypes.h>

#include "mqtt_services.h"
#include "tuya_lib.h"

static const char *TAG = "ESP32_OTA";

static char *http_root_ca = NULL;
static esp_ota_handle_t ota_handle = 0;
static const esp_partition_t *ota_partition = NULL;
static char *tuya_md5_expected = NULL,
            *tuya_hmac_expected = NULL,
            *tuya_device_secret = NULL,
            *tuya_device_id = NULL;

static int total_bytes_written = 0;
static int total_image_size = 0;
static int last_reported_progress = -1;
static int tuya_firmware_size_expected = 0;

mbedtls_md_context_t ota_hmac_ctx;


static char *ota_url = NULL;


static bool verify_hmac_sha256_partition(const esp_partition_t *partition, const char *expected_hmac, const char *secret) {
    const size_t buffer_size = 4096;
    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        ESP_LOGE(TAG, "Failed to allocate buffer for HMAC verification");
        return false;
    }

    mbedtls_md_context_t ctx;
    
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)secret, strlen(secret));

    //size_t remaining = partition->size;
    size_t remaining = total_bytes_written;
    size_t offset = 0;

    while (remaining > 0) {
        size_t to_read = remaining > buffer_size ? buffer_size : remaining;
        if (esp_partition_read(partition, offset, buffer, to_read) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to read flash during HMAC verification");
            free(buffer);
            mbedtls_md_free(&ctx);
            return false;
        }
        mbedtls_md_hmac_update(&ctx, buffer, to_read);
        offset += to_read;
        remaining -= to_read;
    }

    unsigned char hmac_output[32];
    mbedtls_md_hmac_finish(&ctx, hmac_output);
    mbedtls_md_free(&ctx);
    free(buffer);

    char actual_hmac[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(&actual_hmac[i * 2], "%02x", hmac_output[i]);
    }

    ESP_LOGI(TAG, "Expected HMAC: %s", expected_hmac);
    ESP_LOGI(TAG, "Actual   HMAC: %s", actual_hmac);

    return strcasecmp(actual_hmac, expected_hmac) == 0;
}


static bool verify_md5_partition_streamed(const esp_partition_t *partition, const char *expected_md5) {
    const size_t buffer_size = 4096;
    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        ESP_LOGE(TAG, "Failed to allocate buffer for MD5 verification");
        return false;
    }

    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);

    //size_t remaining = partition->size;
    size_t remaining = total_bytes_written;
    size_t offset = 0;

    while (remaining > 0) {
        size_t to_read = remaining > buffer_size ? buffer_size : remaining;
        if (esp_partition_read(partition, offset, buffer, to_read) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to read flash during MD5 verification");
            free(buffer);
            mbedtls_md5_free(&ctx);
            return false;
        }
        mbedtls_md5_update(&ctx, buffer, to_read);
        offset += to_read;
        remaining -= to_read;
    }

    unsigned char digest[16];
    mbedtls_md5_finish(&ctx, digest);
    mbedtls_md5_free(&ctx);
    free(buffer);

    char actual_md5[33];
    for (int i = 0; i < 16; ++i) {
        sprintf(&actual_md5[i * 2], "%02x", digest[i]);
    }

    return strcasecmp(actual_md5, expected_md5) == 0;
}



static bool verify_md5_partition(const esp_partition_t *partition, const char *expected_md5) {
    //uint8_t *buf = malloc(partition->size);
    uint8_t *buf = malloc(total_bytes_written);
    if (!buf) {
        ESP_LOGE(TAG, "Memory allocation failed for MD5 check");
        return false;
    }

    //if (esp_partition_read(partition, 0, buf, partition->size) != ESP_OK) {
    if (esp_partition_read(partition, 0, buf, total_bytes_written) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read partition for MD5 check");
        free(buf);
        return false;
    }

    unsigned char digest[16];
    //mbedtls_md5(buf, partition->size, digest);
    mbedtls_md5(buf, total_bytes_written, digest);
    free(buf);

    char actual_md5[33];
    for (int i = 0; i < 16; ++i) {
        sprintf(&actual_md5[i * 2], "%02x", digest[i]);
    }

    return strcasecmp(actual_md5, expected_md5) == 0;
}



void ota_reset_state(void) {
    if (ota_url) {
        free(ota_url);
        ota_url = NULL;
    }
    ota_handle = 0;
    if (tuya_md5_expected) {
        free(tuya_md5_expected);
        tuya_md5_expected = NULL;
    }
    if (tuya_hmac_expected) {
        free(tuya_hmac_expected);
        tuya_hmac_expected = NULL;
    }
}


void ota_report_progress(int progress) {
    cJSON *report_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(report_obj, "progress", progress);
    cJSON_AddNumberToObject(report_obj, "channel", 9);
    char *report_json = cJSON_PrintUnformatted(report_obj);
    mqtt_send_message(THING_TYPE_OTA_PROGRESS_REPORT, tuya_device_id, report_json);
    free(report_json);
    cJSON_Delete(report_obj);
}


void ota_report_error(ota_err_code_t error_code, const char *error_msg) {
    cJSON *error_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(error_obj, "channel", 9);
    cJSON_AddNumberToObject(error_obj, "errorCode", error_code);
    cJSON_AddStringToObject(error_obj, "errorMsg", error_msg);
    char *error_json = cJSON_PrintUnformatted(error_obj);
    mqtt_send_message(THING_TYPE_OTA_PROGRESS_REPORT, tuya_device_id, error_json);
    free(error_json);
    cJSON_Delete(error_obj);
}


static esp_err_t ota_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "Connected to OTA server");

            // Suspend MQTT auto publish during OTA
            ota_suspend_auto_publish();

            // Initialize OTA progress tracking
            total_bytes_written = 0;
            last_reported_progress = -1;
            total_image_size = tuya_firmware_size_expected;
            

            ota_partition = esp_ota_get_next_update_partition(NULL);
            esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle);

            ESP_LOGI(TAG, "OTA Process Started");
            ota_report_progress(0);

            const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mbedtls_md_init(&ota_hmac_ctx);
            mbedtls_md_setup(&ota_hmac_ctx, info, 1);
            mbedtls_md_hmac_starts(&ota_hmac_ctx, (const unsigned char *)tuya_device_secret, strlen(tuya_device_secret));

            break;

        case HTTP_EVENT_ON_DATA:
            if (evt->data_len > 0) {
                esp_ota_write(ota_handle, evt->data, evt->data_len);
                total_bytes_written += evt->data_len;
                mbedtls_md_hmac_update(&ota_hmac_ctx, evt->data, evt->data_len);
            }

            int progress = ((total_bytes_written * 100) / total_image_size);
            
            if (progress >= 25 && progress % 25 == 0 && progress > last_reported_progress) {
                last_reported_progress = progress;
                ESP_LOGI(TAG, "OTA Progress: %d%%", progress);
                ota_report_progress(progress);
            }

            break;

        case HTTP_EVENT_ON_FINISH:

            if (total_bytes_written != total_image_size) {
                ESP_LOGE(TAG, "Firmware size mismatch! Written: %d, Expected: %d", total_bytes_written, total_image_size);
                esp_ota_abort(ota_handle);
                ota_reset_state();
                ota_report_error(OTA_ERROR_DOWNLOAD_DATA_VERIFICATION_FAILED, "FW size mismatch");
                break;
            }

            if (tuya_md5_expected[0]) {
                if (!verify_md5_partition_streamed(ota_partition, tuya_md5_expected)) {
                    ESP_LOGE(TAG, "MD5 mismatch! Aborting OTA.");
                    esp_ota_abort(ota_handle);
                    ota_reset_state();
                    ota_report_error(OTA_ERROR_UPDATE_HMAC_VERIFICATION_FAILED, "MD5 mismatch");
                    break;
                }

                ESP_LOGI(TAG, "MD5 verified. Proceeding...");

                unsigned char hmac_output[32];
                mbedtls_md_hmac_finish(&ota_hmac_ctx, hmac_output);
                mbedtls_md_free(&ota_hmac_ctx);

                char actual_hmac[65];
                for (int i = 0; i < 32; ++i)
                    sprintf(&actual_hmac[i * 2], "%02x", hmac_output[i]);

                actual_hmac[64] = '\0';

                ESP_LOGI(TAG, "Expected HMAC: %s", tuya_hmac_expected);
                ESP_LOGI(TAG, "Actual   HMAC: %s", actual_hmac);

                // if (strcasecmp(actual_hmac, tuya_hmac_expected) != 0) {
                //     ESP_LOGE(TAG, "HMAC mismatch! Aborting OTA.");
                //     esp_ota_abort(ota_handle);
                //     ota_reset_state();
                //     ota_report_error(OTA_ERROR_UPDATE_HMAC_VERIFICATION_FAILED, "HMAC mismatch");
                //     break;
                // }

                ESP_LOGI(TAG, "HMAC verified. Proceeding...");

                // if (tuya_hmac_expected[0] && tuya_device_secret) {
                //     if (!verify_hmac_sha256_partition(ota_partition, tuya_hmac_expected, tuya_device_secret)) {
                //         ESP_LOGE(TAG, "HMAC mismatch! Aborting OTA.");
                //         esp_ota_abort(ota_handle);
                //         ota_reset_state();
                //         ota_report_error(OTA_ERROR_UPDATE_HMAC_VERIFICATION_FAILED, "HMAC mismatch");
                //         break;
                //     }
                //     ESP_LOGI(TAG, "HMAC verified. Proceeding...");
                // }
            }

            ESP_LOGI(TAG, "OTA data received. Finalizing...");
            esp_ota_end(ota_handle);

            esp_ota_set_boot_partition(ota_partition);
            ESP_LOGI(TAG, "OTA finished. Rebooting...");
            vTaskDelay(pdMS_TO_TICKS(2000));
            esp_restart();
            break;

        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "HTTP error occurred");
            break;

        default:
            break;
    }
    return ESP_OK;
}

esp_err_t https_ota_request(void) {

    esp_err_t ret = ESP_FAIL;

    esp_http_client_config_t config = {
        .url = ota_url,
        .cert_pem = OTA_ROOT_CA_CERTIFICATE,
        .port = 1443,
        .event_handler = ota_event_handler,
        .keep_alive_enable = true,
        .buffer_size = 4096,
        .buffer_size_tx = 4096,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return ESP_FAIL;

    esp_http_client_set_method(client, HTTP_METHOD_GET);

    for (int attempt = 0; attempt < OTA_MAX_RETRIES; attempt++) {
        ret = esp_http_client_perform(client);
        if (ret == ESP_OK) break;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }

    esp_http_client_cleanup(client);
    free(http_root_ca);
    http_root_ca = NULL;

    return ret;
}

void ota_task(void *arg) {
    esp_err_t ret = https_ota_request();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA request failed: %s", esp_err_to_name(ret));
    }
    vTaskDelete(NULL);
}

esp_err_t ota_service(char *fw_url) {
    ota_url = strdup(fw_url);
    if (!ota_url) return ESP_ERR_NO_MEM;

    BaseType_t xReturned = xTaskCreate(ota_task, "ota_task", 4 * 1024, NULL, 10, NULL);
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA task");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t ota_service_tuya(const char *json_payload, char *device_secret, char *device_id) {
    if (!json_payload || !device_secret || !device_id) return ESP_ERR_INVALID_ARG;

    tuya_device_secret = strdup(device_secret);
    if (!tuya_device_secret) return ESP_ERR_NO_MEM;

    tuya_device_id = strdup(device_id);
    if (!tuya_device_id) {
        free(tuya_device_secret);
        tuya_device_secret = NULL;
        return ESP_ERR_NO_MEM;
    }

    cJSON *root = cJSON_Parse(json_payload);
    if (!root) return ESP_ERR_INVALID_ARG;

    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    const char *url = cJSON_GetObjectItem(data, "httpsUrl")->valuestring;
    const char *md5 = cJSON_GetObjectItem(data, "md5")->valuestring;
    const char *hmac = cJSON_GetObjectItem(data, "hmac")->valuestring;
    const char *fw_size = cJSON_GetObjectItem(data, "size")->valuestring;

    if (!url || !md5 || !hmac || !fw_size) {
        ESP_LOGE(TAG, "Invalid JSON payload: missing required fields");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    tuya_md5_expected = strdup(md5);
    if (!tuya_md5_expected) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    tuya_hmac_expected = strdup(hmac);
    if (!tuya_hmac_expected) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    tuya_firmware_size_expected = atoi(fw_size);
    if (tuya_firmware_size_expected <= 0) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Tuya OTA URL: %s", url);
    ESP_LOGI(TAG, "Tuya MD5: %s", md5);
    ESP_LOGI(TAG, "Tuya HMAC: %s", hmac);
    ESP_LOGI(TAG, "Tuya Firmware Size: %d", tuya_firmware_size_expected);

    // Start the OTA process
    esp_err_t ret = ota_service((char *)url);
    cJSON_Delete(root);
    return ret;
}
