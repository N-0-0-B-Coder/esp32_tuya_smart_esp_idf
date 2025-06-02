#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include <inttypes.h>

static const char *TAG = "OTA_TEST";

void dump_otadata(void) {
    const esp_partition_t *otadata = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, NULL);
    if (!otadata) {
        ESP_LOGE(TAG, "Failed to find otadata partition");
        return;
    }

    uint8_t buf[32];
    esp_partition_read(otadata, 0, buf, sizeof(buf));
    ESP_LOG_BUFFER_HEX("OTADATA", buf, sizeof(buf));
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting OTA test...");

    const esp_partition_t *running = esp_ota_get_running_partition();
    ESP_LOGI(TAG, "Running partition: %s @ 0x%" PRIx32, running->label, running->address);

    const esp_partition_t *next = esp_ota_get_next_update_partition(running);
    ESP_LOGI(TAG, "Next partition to set: %s @ 0x%" PRIx32, next->label, next->address);

    esp_err_t ret = esp_ota_set_boot_partition(next);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "esp_ota_set_boot_partition() succeeded.");
    } else {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition() failed: %s", esp_err_to_name(ret));
    }

    ESP_LOGI(TAG, "Reading OTA data after partition change...");
    dump_otadata();

    ESP_LOGI(TAG, "Waiting 10s before reboot...");
    vTaskDelay(pdMS_TO_TICKS(10000));
    esp_restart();
}
