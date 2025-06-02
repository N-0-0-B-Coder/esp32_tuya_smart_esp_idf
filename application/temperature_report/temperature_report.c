#include "temperature_report.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"


int temperature = 0;

#ifdef TUYA_MQTT

int get_temperature(void) {
    return temperature;
}

void temperature_data_task(void *arg) {
    for (;;) {
        temperature = ((int)(((float)rand() / RAND_MAX) * 10000));

        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

void tuya_temperature_report(void) {
    // Create a task to generate temperature data
    xTaskCreate(temperature_data_task, "temperature_data_task", 1024, NULL, 4, NULL);
}

#endif

#ifdef AWS_MQTT

void publish_json_data() {
    char *json_string = NULL;

    for (;;) {
        if (mqtt_connected) {
            // Create the root JSON object
            cJSON *root = cJSON_CreateObject();
            if (root == NULL) {
                ESP_LOGE(TAG, "Failed to create root JSON object");
                vTaskDelay(pdMS_TO_TICKS(1000)); // Delay 1 seconds
                continue;
            }

            // Add "created_at" field
            time_t now = time(NULL);
            cJSON_AddNumberToObject(root, "created_at", now);

            // Add "device" object
            cJSON *device = cJSON_CreateObject();
            if (device == NULL) {
                ESP_LOGE(TAG, "Failed to create device JSON object");
                cJSON_Delete(root);
                vTaskDelay(pdMS_TO_TICKS(1000)); // Delay 1 seconds
                continue;
            }
            cJSON_AddStringToObject(device, "serial_number", device_id);
            cJSON_AddStringToObject(device, "firmware_version", firmware_version);
            cJSON_AddItemToObject(root, "device", device);

            // Add "data" array
            cJSON *data_array = cJSON_CreateArray();
            if (data_array == NULL) {
                ESP_LOGE(TAG, "Failed to create data JSON array");
                cJSON_Delete(root);
                vTaskDelay(pdMS_TO_TICKS(1000)); // Delay 100 seconds
                continue;
            }

            // Add first sensor data (velocity)
            cJSON *velocity = cJSON_CreateObject();
            if (velocity != NULL) {
                float random_value = ((float)rand() / RAND_MAX) * 100.0f; // Random value between 0.0 and 99.9
                char random_value_str[10];
                snprintf(random_value_str, sizeof(random_value_str), "%.1f", random_value);
                cJSON_AddStringToObject(velocity, "name", "velocity");
                cJSON_AddStringToObject(velocity, "value", random_value_str);
                cJSON_AddStringToObject(velocity, "unit", "km/h");
                cJSON_AddStringToObject(velocity, "series", "v");
                cJSON_AddNumberToObject(velocity, "timestamp", now);
                cJSON_AddItemToArray(data_array, velocity);
            }

            // Add second sensor data (frequency)
            cJSON *frequency = cJSON_CreateObject();
            if (frequency != NULL) {
                int16_t random_value = rand() % 100; // Random value between 0 and 99
                char random_value_str[10];
                snprintf(random_value_str, sizeof(random_value_str), "%d", random_value);
                cJSON_AddStringToObject(frequency, "name", "frequency");
                cJSON_AddStringToObject(frequency, "value", random_value_str);
                cJSON_AddStringToObject(frequency, "unit", "Hz");
                cJSON_AddStringToObject(frequency, "series", "f");
                cJSON_AddNumberToObject(frequency, "timestamp", now);
                cJSON_AddItemToArray(data_array, frequency);
            }

            cJSON_AddItemToObject(root, "data", data_array);

            // Convert JSON object to string
            json_string = cJSON_PrintUnformatted(root);
            if (json_string == NULL) {
                ESP_LOGE(TAG, "Failed to print JSON object");
                cJSON_Delete(root);
                vTaskDelay(pdMS_TO_TICKS(1000)); // Delay 100 seconds
                continue;
            }

            // Publish the JSON string via MQTT
            int ret = esp_mqtt_client_publish(client, "/topic/data", json_string, 0, 1, 0);

            if (ret < 0) {
                ESP_LOGE(TAG, "Failed to publish MQTT message: %d", ret);
            } else {
                ESP_LOGI(TAG, "Published JSON: %s", json_string);
            }

            // Free allocated memory
            cJSON_Delete(root);
            free(json_string);
        } else {
            ESP_LOGW(TAG, "MQTT client is not connected. Skipping publish.");
        }

        // Delay 100 seconds
        vTaskDelay(pdMS_TO_TICKS(100000));
    }
}

void mqtt_ping_task(void *arg) {
    for (;;) {
        if (mqtt_connected) {
            esp_mqtt_client_publish(client, "/topic/ping", "1", 0, 1, 0);
            ESP_LOGI(TAG, "MQTT ping sent to keep connection alive");
        } else {
            ESP_LOGW(TAG, "MQTT client is not connected. Skipping ping.");
        }

        vTaskDelay(pdMS_TO_TICKS(50000));  // Ping every 50 seconds
    }
}

#endif