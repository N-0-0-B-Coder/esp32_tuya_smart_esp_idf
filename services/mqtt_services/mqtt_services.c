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

#include "tuya_lib.h"

#include "mqtt_client.h"

#include "http_services.h"
#include "temperature_report.h"

static const char *TAG = "ESP32_MQTT";

static int s_retry_num = 0;

bool mqtt_connected = false,
     mqtt_ota = false;
esp_mqtt_client_handle_t client;
char *mqtt_root_ca = TUYA_CA_CERTIFICATE,
     *mqtt_device_cert = DEVICE_CERTIFICATE,
     *mqtt_private_key = PRIVATE_KEY,
     *firmware_version = NULL,
     *tuya_clientID = NULL,
     *tuya_username = NULL,
     *tuya_password = NULL;

const char  *productId = "9riqm9xovtawbe0w",
            *deviceId = "261c89e899ea62efd9gshz",
            *deviceSecret = "a6fnuehkV7TLDp9t";


static char mqtt_topic[MAX_TOPIC_LENGTH];
static char mqtt_payload[MAX_PAYLOAD_LENGTH];
static int mqtt_payload_len = 0;


static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
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

        // char data_string[256];

        // snprintf(data_string, 256, "{\"data\":{\"Temp_Value\":65},\"time\":%d}", (int)time(NULL));
        // message = (tuyalink_message_t){
        //     .type = THING_TYPE_PROPERTY_REPORT,
        //     .device_id = NULL,
        //     .data_string = data_string
        // };
        // msg_id = tuya_message_send(client, deviceId, &message);

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

void publish_data() {
    for (;;) {
        if (mqtt_connected) {
            tuyalink_message_t message;
            char data_string[128];
            int temperature = get_temperature();
            snprintf(data_string, sizeof(data_string),
                "{\"Temp\":{\"value\":%d,\"time\":%d}}",
                temperature, (int)time(NULL));
            message.type = THING_TYPE_PROPERTY_REPORT;
            message.device_id = NULL;
            message.data_string = data_string;
            tuya_message_send(client, deviceId, &message);
            vTaskDelay(pdMS_TO_TICKS(10000)); // Report every 10 seconds
        } else {
            ESP_LOGW(TAG, "MQTT client is not connected. Skipping publish.");
        }
        vTaskDelay(pdMS_TO_TICKS(10000)); // Delay 10 seconds before next publish
    }
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
    ESP_LOGI(TAG, "Start publishing data to MQTT broker...");
    xTaskCreate(publish_data, "mqtt_publish_task", 2560, NULL, 6, NULL);
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