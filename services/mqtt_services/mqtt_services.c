#include "mqtt_services.h"
#include "cJSON.h"

#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_sntp.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "mqtt_client.h"
#include "ota_services.h"
#include "http_services.h"
#include "temperature_report.h"
#include "humidity_report.h"

static const char *TAG = "ESP32_MQTT";

esp_mqtt_client_handle_t client;

static int s_retry_num = 0;

// MQTT connection status
bool mqtt_connected = false,
     mqtt_ota = false,
     is_ota_done = false,
     is_ota_doing = false;

// Tuya MQTT credentials
char *mqtt_root_ca = TUYA_CA_CERTIFICATE,
     *mqtt_device_cert = DEVICE_CERTIFICATE,
     *mqtt_private_key = PRIVATE_KEY,
     *tuya_clientID = NULL,
     *tuya_username = NULL,
     *tuya_password = NULL;

// Tuya device information
const char  *productId = "kr86og4kc8kkcpqk",
            *deviceId = "26f95593d293fe5197qhpy",
            *deviceSecret = "9ur3Gwzk4zzLHuwR",
            *firmwareKey = "keypfnqy8uv4n8y3";

// MQTT topic and payload buffers
static char mqtt_topic[MAX_TOPIC_LENGTH];
static char mqtt_payload[MAX_PAYLOAD_LENGTH];
static int mqtt_payload_len = 0;

// Temperature conditions
char temp_condition[50];

// Tuya MQTT OTA JSON data
// cJSON objects for parsing MQTT messages
cJSON *ota_init = NULL;

// Prototype definitions
uint8_t check_mqtt_topic(char *topic, char *data);
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);


// Functions

void mqtt_after_ota(void) {
    is_ota_done = true;
}

void ota_suspend_auto_publish(void) {
    is_ota_doing = false;
}


static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

void fw_ver_init(void *arg) {
    // Initialize the firmware version
    esp_app_desc_t *app_desc = esp_app_get_description();
    char *firmware_version = app_desc->version;
    if (firmware_version != NULL) {
        ESP_LOGI(TAG, "Firmware version: %s", firmware_version);
    } else {
        ESP_LOGE(TAG, "Failed to allocate memory for firmware version");
        vTaskDelete(NULL);
    }

    ota_init = cJSON_CreateObject();
    if (is_ota_done) {
        cJSON_AddStringToObject(ota_init, "bizType", "UPDATE");
        is_ota_done = false; // Reset the flag after processing
    } else {
        cJSON_AddStringToObject(ota_init, "bizType", "INIT");
    }
    cJSON_AddStringToObject(ota_init, "pid", productId);
    cJSON_AddStringToObject(ota_init, "firmwareKey", firmwareKey);

    cJSON *ota_channel_array = cJSON_CreateArray();
    cJSON *channel_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(channel_obj, "channel", 9);
    cJSON_AddStringToObject(channel_obj, "version", firmware_version);
    cJSON_AddItemToArray(ota_channel_array, channel_obj);

    cJSON_AddItemToObject(ota_init, "otaChannel", ota_channel_array);
    vTaskDelete(NULL);
}


uint8_t check_mqtt_topic(char *topic, char *data) {
    if (topic == NULL || data == NULL) {
        ESP_LOGE(TAG, "Topic or data is NULL");
        return -1;
    }
    
    //ESP_LOGI(TAG, "Topic: %s", topic);

    if (strstr(topic, "/thing/property/set") != NULL) {
        cJSON *json = cJSON_Parse(data);
        if (json == NULL) {
            ESP_LOGE(TAG, "Failed to parse OTA JSON data");
            return -1;
        }

        cJSON *data_obj = cJSON_GetObjectItem(json, "data");
        if (data_obj == NULL) {
            ESP_LOGE(TAG, "Failed to get 'data' object from JSON");
            cJSON_Delete(json);
            return -1;
        }

        // Extract the "Led_SW" property from the JSON data
        cJSON *led_sw_item = cJSON_GetObjectItem(data_obj, "Led_SW");
        if (led_sw_item == NULL) {
            ESP_LOGE(TAG, "No 'Led_SW' property found in 'set' command");
        } else {
            bool led_sw = cJSON_IsTrue(led_sw_item);
            if (led_sw) {
                ESP_LOGI(TAG, "Turning on LED");
            } else {
                ESP_LOGI(TAG, "Turning off LED");
            }

            // Respond to the property set request
            char data_string[128];
            snprintf(data_string, sizeof(data_string), "{\"Led_SW\":%s}", led_sw ? "true" : "false");
            mqtt_send_message(THING_TYPE_PROPERTY_REPORT, deviceId, data_string);
        }

        cJSON_Delete(json);
    } else if (strstr(topic, "/thing/model/get_response") != NULL) {
        ESP_LOGI(TAG, "Received model get response");
    } else if (strstr(topic, "ota/issue") != NULL) {
        ota_service_tuya(mqtt_payload, deviceSecret, deviceId);
    } else {
        ESP_LOGW(TAG, "Unknown topic: %s", topic);
    }

    return 0;
}


static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected to broker.");

        // Subscribe to the topics
        tuya_subcribe(client, deviceId, 1);
        
        // Publish a test message
        tuyalink_message_t message = {
		.type = THING_TYPE_MODEL_GET,
		.device_id = NULL,
		.data_string = "{\"format\":\"simple\"}"
	    };
        msg_id = tuya_message_send(client, deviceId, &message);

        // Publish the device initialization firmware version
        if (ota_init != NULL) {
            char *ota_json_string = cJSON_PrintUnformatted(ota_init);
            if (ota_json_string != NULL) {
                message.type = THING_TYPE_OTA_FIRMWARE_REPORT;
                message.data_string = ota_json_string;
                tuya_message_send(client, deviceId, &message);
                free(ota_json_string);
            } else {
                ESP_LOGE(TAG, "Failed to create OTA JSON string");
            }
        } else {
            ESP_LOGE(TAG, "OTA initialization JSON is NULL");
        }
        

        //msg_id = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
        //ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        //msg_id = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
        //ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);

        mqtt_connected = true;
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT disconnected.");
        mqtt_connected = false;
        mqtt_ota = false;

        wifi_ap_record_t ap_info;

        if (s_retry_num < ESP_MQTT_MAXIMUM_RETRY) {
            int delay_time = (1 << s_retry_num) * 1000; // 1s, 2s, 4s, etc.
            vTaskDelay(pdMS_TO_TICKS(delay_time));
            if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
                ESP_LOGI(TAG, "Retrying MQTT connection...");
                esp_err_t ret = esp_mqtt_client_reconnect(client);
                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to reconnect to MQTT broker: %s", esp_err_to_name(ret));
                } else {
                    ESP_LOGI(TAG, "Reconnected to MQTT broker.");
                    mqtt_connected = true;
                    mqtt_ota = true;
                }
            }
            
            s_retry_num++;
        }

        break;

    case MQTT_EVENT_SUBSCRIBED:
        //ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        //ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        //ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:

        //ESP_LOGI(TAG, "MQTT_EVENT_DATA");

        // First chunk of message
        if (event->current_data_offset == 0) {
            memset(mqtt_payload, 0, sizeof(mqtt_payload));
            memset(mqtt_topic, 0, sizeof(mqtt_topic));
            mqtt_payload_len = 0;

            int topic_len = event->topic_len < MAX_TOPIC_LENGTH - 1 ? event->topic_len : MAX_TOPIC_LENGTH - 1;
            memcpy(mqtt_topic, event->topic, topic_len);
            mqtt_topic[topic_len] = '\0';
        }

        // Append this chunk to the payload buffer
        if (mqtt_payload_len + event->data_len < MAX_PAYLOAD_LENGTH) {
            memcpy(mqtt_payload + mqtt_payload_len, event->data, event->data_len);
            mqtt_payload_len += event->data_len;
        } else {
            ESP_LOGW(TAG, "MQTT payload too large. Data truncated.");
        }

        // Final chunk
        if (event->current_data_offset + event->data_len == event->total_data_len) {
            mqtt_payload[mqtt_payload_len] = '\0';  // Null-terminate
            ESP_LOGI(TAG, "Complete TOPIC: %s", mqtt_topic);
            ESP_LOGI(TAG, "Complete DATA: %s", mqtt_payload);
        }
        
        // Check the MQTT
        if (check_mqtt_topic(mqtt_topic, mqtt_payload) != 0) {
            ESP_LOGE(TAG, "Failed to check MQTT topic or data");
        }

        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));

        }
        break;

    case MQTT_EVENT_BEFORE_CONNECT:
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

void auto_publish_data() {
    for (;;) {
        if (is_ota_doing) {
            vTaskDelay(pdMS_TO_TICKS(30000)); // Delay 30 seconds before next check
            continue;
        }
        if (mqtt_connected) {

            ESP_LOGI(TAG, "Start publishing data to MQTT broker...");

            // Prepare the message to publish
            tuyalink_message_t message;
            message.type = THING_TYPE_PROPERTY_REPORT;
            message.device_id = NULL;


            char data_string[128];
            int temperature = get_temperature();
            int humidity = get_humidity();
            int timestamp = (int)time(NULL);
            cJSON *root = cJSON_CreateObject();

            // Create JSON objects for temperature
            cJSON *temp_obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(temp_obj, "value", temperature);
            cJSON_AddNumberToObject(temp_obj, "time", timestamp);

            cJSON_AddItemToObject(root, "Temp_Value", temp_obj);

            // Create JSON objects for humidity
            cJSON *humi_obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(humi_obj, "value", humidity);
            cJSON_AddNumberToObject(humi_obj, "time", timestamp);

            cJSON_AddItemToObject(root, "Humi_Value", humi_obj);

            snprintf(data_string, sizeof(data_string), "%s", cJSON_PrintUnformatted(root));
            cJSON_Delete(root);
            
            message.data_string = data_string;
            tuya_message_send(client, deviceId, &message);

            // Track last sent temperature condition to prevent repetitive sending
            static char last_temp_condition[50] = "";

            if (temperature <= 2000) {
                strcpy(temp_condition, "Cold Temperature");
            } else if (temperature >= 8000) {
                strcpy(temp_condition, "Hot Temperature");
            } else {
                strcpy(temp_condition, "Normal Temperature");
            }

            // Only send if temp_condition changed from last sent
            if (strcmp(temp_condition, last_temp_condition) != 0) {
                message.type = THING_TYPE_EVENT_TRIGGER;

                cJSON *event_root = cJSON_CreateObject();
                cJSON_AddStringToObject(event_root, "eventCode", "Temp_Alarm");
                cJSON_AddNumberToObject(event_root, "eventTime", timestamp);
                cJSON *output_params = cJSON_CreateObject();
                cJSON_AddStringToObject(output_params, "temp_condition", temp_condition);
                cJSON_AddItemToObject(event_root, "outputParams", output_params);

                snprintf(data_string, sizeof(data_string), "%s", cJSON_PrintUnformatted(event_root));
                message.data_string = data_string;
                tuya_message_send(client, deviceId, &message);

                strcpy(last_temp_condition, temp_condition);
                cJSON_Delete(event_root);
            } else {
                ESP_LOGI(TAG, "Temperature condition '%s' already sent. No event triggered.", temp_condition);
            }
        } else {
            ESP_LOGW(TAG, "MQTT client is not connected. Skipping publish.");
        }
        vTaskDelay(pdMS_TO_TICKS(30000)); // Delay 30 seconds before next publish
    }
}

esp_err_t mqtt_send_message(tuyalink_thing_type_t type, const char *deviceId, char *data_string) {
    esp_err_t ret = ESP_FAIL;
    if (client == NULL || deviceId == NULL || data_string == NULL) {
        ESP_LOGE(TAG, "Invalid parameters for mqtt_send_message");
        return ESP_ERR_INVALID_ARG;
    }

    tuyalink_message_t message = {
        .type = type,
        .device_id = NULL,
        .data_string = data_string,
        .ack = false
    };

    ret = tuya_message_send(client, deviceId, &message);
    return ret;
}


int initialize_sntp(void) {
    int ret = ESP_OK;
    if (!esp_sntp_enabled()) {
    ESP_LOGI("SNTP", "Initializing SNTP");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org"); // Use the default NTP server
    esp_sntp_init();
    }

    // Wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while (timeinfo.tm_year < (1970 - 1900) && ++retry < retry_count) {
        ESP_LOGI("SNTP", "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(pdMS_TO_TICKS(2000)); // Wait 2 seconds
        time(&now);
        localtime_r(&now, &timeinfo);
    }

    if (timeinfo.tm_year < (1970 - 1900)) {
        ESP_LOGE("SNTP", "Failed to synchronize time");
    } else {
        ESP_LOGI("SNTP", "System time synchronized: %s", asctime(&timeinfo));
    }

    uint8_t count = 10;
    // Wait SNTP is enabled
    while (!esp_sntp_enabled() && count > 0) {
        ESP_LOGI("SNTP", "Waiting for SNTP to be enabled...");
        vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second
        count--;
    }

    if (count == 0) {
        ESP_LOGE("SNTP", "SNTP is not enabled after 10 seconds");
        return ESP_FAIL;
    }

    return ret;
}

static void mqtt_app_start(void) {
    int ret = ESP_OK;
    srand(time(NULL));

    // Initialize SNTP to synchronize time
    initialize_sntp();

    /* Device token signature */
    tuya_clientID = malloc(TUYA_CLIENTID_LEN);
    tuya_username = malloc(TUYA_USERNAME_LEN);
    tuya_password = malloc(TUYA_PASSWORD_LEN);

    if (!tuya_clientID || !tuya_username || !tuya_password) {
    ESP_LOGE(TAG, "Failed to allocate memory for Tuya MQTT credentials");
    // Handle error, e.g., return or restart
    return;
    }

    memset(tuya_clientID, 0, TUYA_CLIENTID_LEN);
    memset(tuya_username, 0, TUYA_USERNAME_LEN);
    memset(tuya_password, 0, TUYA_PASSWORD_LEN);
    ret = tuya_mqtt_auth_signature_calculate(deviceId, deviceSecret, tuya_clientID, tuya_username, tuya_password);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate Tuya MQTT authentication signature: %s", esp_err_to_name(ret));
        return;
    }

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = TUYA_BROKER_URL,
        .broker.verification.certificate = mqtt_root_ca,
        .credentials = {
            .client_id = tuya_clientID,
            .username = tuya_username,
            .authentication = {
                .password = tuya_password,
            },
        }
    };

    ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);

    xTaskCreate(auto_publish_data, "auto_publish_task", 2560, NULL, 6, NULL);
    //xTaskCreate(mqtt_ping_task, "mqtt_ping_task", 1024, NULL, 5, NULL);
}

void mqtt_task(void *arg) {
    //ESP_LOGI(TAG, "[APP] Startup..");
    //ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    //ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("mqtt_client", ESP_LOG_VERBOSE);
    esp_log_level_set("transport_base", ESP_LOG_VERBOSE);
    esp_log_level_set("transport", ESP_LOG_VERBOSE);
    esp_log_level_set("outbox", ESP_LOG_VERBOSE);

    // ESP_ERROR_CHECK(nvs_flash_init());
    // ESP_ERROR_CHECK(esp_netif_init());
    // ESP_ERROR_CHECK(esp_event_loop_create_default());

    mqtt_app_start();

    ESP_LOGI(TAG, "MQTT task remaining stack: %d bytes", uxTaskGetStackHighWaterMark(NULL));
    for (;;) {
        vTaskDelay(1);
    }
}

esp_err_t mqtt_service(void)
{
    // Prepare the initialization firmware version
    xTaskCreate(fw_ver_init, "fw_ver_init", 2048, NULL, 5, NULL);

    BaseType_t xReturned;
    uint8_t count = 0;
    xReturned = xTaskCreate(mqtt_task, "mqtt_task", 3 * 1024, NULL, 5, NULL);
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create MQTT task");
        return ESP_FAIL;
    }
    while (mqtt_connected != true && count < 10) {
        count++;
        ESP_LOGI(TAG, "Waiting for MQTT connection...");
        vTaskDelay(pdMS_TO_TICKS(2000));  // Wait for 2 second before retrying
    }
    if (count == 10) {
        ESP_LOGE(TAG, "Failed to connect to MQTT broker after 10 attempts. Exiting MQTT task.");
        return ESP_FAIL;
    }
    return ESP_OK;
}