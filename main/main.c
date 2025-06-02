#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "wifi_services.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"

#include "input.h"
#include "temperature_report.h"

static const char *TAG = "ESP32_MAIN";


// Prototypes
void input_handler(uint32_t gpio_num);



// Function to validate OTA state at startup
void boot_validation(void) {
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;

    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        ESP_LOGI(TAG, "Running partition: %s @ 0x%" PRIx32, running->label, running->address);
        ESP_LOGI(TAG, "OTA state: %d", ota_state);

        switch (ota_state) {
            case ESP_OTA_IMG_PENDING_VERIFY:
                ESP_LOGI(TAG, "Firmware pending verification.");
                if (true /* TODO: Replace with actual check */) {
                    ESP_LOGI(TAG, "Marking firmware as valid.");
                    esp_ota_mark_app_valid_cancel_rollback();
                } else {
                    ESP_LOGE(TAG, "Firmware check failed! Rolling back.");
                    esp_ota_mark_app_invalid_rollback_and_reboot();
                }
                break;

            case ESP_OTA_IMG_VALID:
                ESP_LOGI(TAG, "Firmware is valid.");
                break;

            case ESP_OTA_IMG_INVALID:
                ESP_LOGE(TAG, "Firmware marked invalid. Rolling back...");
                esp_ota_mark_app_invalid_rollback_and_reboot();
                break;

            default:
                ESP_LOGW(TAG, "Unknown OTA state: %d", ota_state);
                break;
        }
    } else {
        ESP_LOGE(TAG, "Failed to get OTA state.");
    }

    ESP_LOGI(TAG, "OTA validation complete.");
}

// Function to initialize NVS and log boot partition
void app_init(void) {
    const esp_partition_t *part = esp_ota_get_boot_partition();
    ESP_LOGI(TAG, "Booting from: %s", part->label);

    ESP_LOGI(TAG, "Initializing NVS...");
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS initialized.");
}



// Main application
void app_main(void)
{
    boot_validation();   // Validate OTA
    app_init();          // Initialize NVS flash
    ESP_LOGI(TAG, "***********************************");
    ESP_LOGI(TAG, "*                                 *");
    ESP_LOGI(TAG, "*            This is              *");
    ESP_LOGI(TAG, "* version 1.0 of the application. *");
    ESP_LOGI(TAG, "*                                 *");
    ESP_LOGI(TAG, "***********************************");

    ESP_LOGI(TAG, "Starting main application...");

    tuya_temperature_report();

    // Start Wi-Fi service
    while (wifi_service() != ESP_OK) {
        ESP_LOGI(TAG, "Retrying Wi-Fi connection...");
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    /* Set the callback function */
    //input_set_callback(&input_handler);

    /* Start the input task */
    //input_app();
}



// void input_handler(uint32_t gpio_num) {
//     int ret = gpio_get_level(gpio_num);
//     input_set_queue(ret);
// }