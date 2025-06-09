#include "ota_services.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"

#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_rom_crc.h"
#include <inttypes.h>

#include "http_services.h"

static const char *TAG = "ESP32_OTA";

static char *http_root_ca = NULL;

static esp_ota_handle_t ota_handle = 0;
static const esp_partition_t *ota_partition = NULL;
static uint32_t crc_accumulator = 0xFFFFFFFF;  // CRC32 accumulator (init to 0xFFFFFFFF)

static char *ota_url = NULL;
static uint32_t server_crc = 0;

// Helper function for check_ca_cert
static esp_err_t get_string_from_nvs(nvs_handle_t nvs_handle, const char *key, char **out_value) {
    size_t required_size = 0;
    esp_err_t err = nvs_get_str(nvs_handle, key, NULL, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Key '%s' not found in NVS", key);
        *out_value = NULL;
        nvs_close(nvs_handle);
        return ESP_FAIL;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get size for key '%s': %s", key, esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    *out_value = (char *)malloc(required_size);
    if (*out_value == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for key '%s'", key);
        return ESP_ERR_NO_MEM;
    }
    //required_size = strlen(*out_value) + 1;
    err = nvs_get_str(nvs_handle, key, *out_value, &required_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get value for key '%s': %s", key, esp_err_to_name(err));
        free(*out_value);
        nvs_close(nvs_handle);
    }
    return err;
}



esp_err_t retrieve_ca_cert(char **out_root_ca) {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    // Open NVS storage with the same namespace (e.g., "certs")
    err = nvs_open("certs", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    // Retrieve each certificate/key
    err = get_string_from_nvs(nvs_handle, "root_ca", out_root_ca);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve root_ca");
    }

    // Close the NVS handle
    nvs_close(nvs_handle);
    return ESP_OK;
}


void reset_ota_state(void) {
    if (ota_url) {
        free(ota_url);
        ota_url = NULL;
    }
    ota_handle = 0;
    crc_accumulator = 0xFFFFFFFF;
    server_crc = 0;
}


static uint32_t crc32_le(uint32_t crc, const uint8_t *buf, size_t len) {
    while (len--) {
        crc ^= *buf++;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
    return crc;
}

static esp_err_t ota_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "Connected to OTA server");
            ota_partition = esp_ota_get_next_update_partition(NULL);
            ESP_LOGI(TAG, "Writing to partition: %s at offset 0x%" PRIx32,
                     ota_partition->label, ota_partition->address);
            esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle);
            crc_accumulator = 0xFFFFFFFF;
            break;

        case HTTP_EVENT_ON_DATA:
            if (evt->data_len > 0) {
                esp_ota_write(ota_handle, evt->data, evt->data_len);
                crc_accumulator = crc32_le(crc_accumulator, (const uint8_t *)evt->data, evt->data_len);
                //crc_accumulator = esp_rom_crc32_le(crc_accumulator, (const uint8_t *)evt->data, evt->data_len);
            }
            break;

        case HTTP_EVENT_ON_FINISH:
            uint32_t calculated_crc = crc_accumulator ^ 0xFFFFFFFF;
            if (calculated_crc != server_crc) {
                ESP_LOGE(TAG, "CRC mismatch! Server: 0x%" PRIx32 ", Calculated: 0x%" PRIx32". Aborting OTA!",
                         server_crc, calculated_crc);
                esp_ota_abort(ota_handle);
                reset_ota_state();
                break;
            }

            ESP_LOGI(TAG, "Server: 0x%"PRIx32", Calculated: 0x%" PRIx32". CRC match! Proceeding...", 
                server_crc, calculated_crc);
                
            esp_ota_end(ota_handle);

            vTaskDelay(pdMS_TO_TICKS(3000));
            ESP_LOGI(TAG, "OTA finished.");

            esp_ota_set_boot_partition(ota_partition);
            ESP_LOGI(TAG, "Boot partition set to: %s", ota_partition->label);
            vTaskDelay(pdMS_TO_TICKS(2000));
            ESP_LOGI(TAG, "Rebooting device...");
            esp_restart();
            break;

        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "HTTP error occurred");
            break;

        case HTTP_EVENT_HEADERS_SENT:
            break;

        case HTTP_EVENT_ON_HEADER:
            break;

        default:
            ESP_LOGI(TAG, "HTTP event: %d", evt->event_id);
            break;
    }
    return ESP_OK;
}


esp_err_t https_ota_request(void) {

    esp_err_t ret = ESP_FAIL;

    ESP_LOGI(TAG, "Starting OTA request...");

    ret = retrieve_ca_cert(&http_root_ca);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve CA Cert from NVS: %s", esp_err_to_name(ret));
        return ret;
    }


    esp_http_client_config_t config = {
        .url = ota_url,
        .cert_pem = ROOT_CA_CERTIFICATE,
        .port = 443,
        .event_handler = ota_event_handler,
        .keep_alive_enable = true,
        .buffer_size = 4096,                // (Rx) default is 512
        .buffer_size_tx = 4096,             // (Tx) default is 512, optional
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        free(http_root_ca);
        http_root_ca = NULL;
        return ESP_FAIL;
    }
    
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    //esp_http_client_set_header(client, "Content-Type", "application/json");

    for (int attempt = 0; attempt < OTA_MAX_RETRIES; attempt++) {
        ret = esp_http_client_perform(client);
        if (ret == ESP_OK) {
            break;
        } else {
            ESP_LOGW(TAG, "OTA try %d failed, retrying...", attempt + 1);
            vTaskDelay(pdMS_TO_TICKS(3000));
        }
    }

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, Content Length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP Request failed: %s", esp_err_to_name(ret));
    }

    // Cleanup
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

    ESP_LOGI(TAG, "OTA task remaining stack: %d bytes", uxTaskGetStackHighWaterMark(NULL));
    vTaskDelete(NULL);
}



esp_err_t ota_service(char *fw_url, uint32_t expected_crc) {
    server_crc = expected_crc;
    ota_url = strdup(fw_url);
    BaseType_t xReturned;
    xReturned = xTaskCreate(ota_task, "ota_task", 4 * 1024, NULL, 10, NULL);
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA task");
        return ESP_FAIL;
    }
    return ESP_OK;
}