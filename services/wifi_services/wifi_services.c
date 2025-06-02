#include "wifi_services.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "mqtt_client.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "output.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "http_services.h"
#include "mqtt_services.h"

static const char *TAG = "ESP32_WIFI";

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

static int s_retry_num = 0;

char *root_ca = NULL,
      *device_cert = NULL,
      *private_key = NULL,
      *public_key = NULL;

char *mac2str(uint8_t mac[6]) {
    static char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}


static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                //ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
                esp_wifi_connect();
                break;
                
            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG,"connect to the AP fail");
                wifi_event_sta_disconnected_t* disconnected = (wifi_event_sta_disconnected_t*) event_data;
                ESP_LOGW(TAG, "Disconnected. Reason: %d", disconnected->reason);
                if (s_retry_num < ESP_WIFI_MAXIMUM_RETRY) {
                    int delay_time = (1 << s_retry_num) * 1000; // 1s, 2s, 4s, etc.
                    vTaskDelay(pdMS_TO_TICKS(delay_time));
                    ESP_LOGI(TAG, "Retrying WiFi connection...");
                    esp_wifi_connect();
                    s_retry_num++;
                } else {
                    xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                }
                break;

            case WIFI_EVENT_STA_CONNECTED:
                wifi_event_sta_connected_t* connected = (wifi_event_sta_connected_t*) event_data;
                ESP_LOGI(TAG, "Connected to AP. SSID: %s", connected->ssid);
                ESP_LOGI(TAG, "BSSID: %02x:%02x:%02x:%02x:%02x:%02x", connected->bssid[0], connected->bssid[1], 
                    connected->bssid[2], connected->bssid[3], connected->bssid[4], connected->bssid[5]);
                break;

            case WIFI_EVENT_STA_BSS_RSSI_LOW:
                wifi_event_bss_rssi_low_t* rssi_low = (wifi_event_bss_rssi_low_t*) event_data;
                ESP_LOGI(TAG, "RSSI of BSS is low: %ld", rssi_low->rssi);
                break;

            case WIFI_EVENT_HOME_CHANNEL_CHANGE:
                //ESP_LOGI(TAG, "WIFI_EVENT_HOME_CHANNEL_CHANGE");
                ESP_LOGI(TAG, "Channel changed to %d", ((wifi_event_home_channel_change_t*) event_data)->new_chan);
                break;

            default:
                ESP_LOGW(TAG, "UNHANDLED EVENT, event_base: %s, event_id: %ld", event_base, event_id);
                break;
        }

    } else if (event_base == IP_EVENT) {
        switch (event_id) {
            case IP_EVENT_STA_GOT_IP:
                //ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP");
                ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
                ESP_LOGI(TAG, "IP Asigned:" IPSTR, IP2STR(&event->ip_info.ip));
                s_retry_num = 0;
                xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);


                wifi_ap_record_t ap_info;
                if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
                    ESP_LOGI(TAG, "RSSI: %d", ap_info.rssi);
                } else {
                    ESP_LOGE(TAG, "Failed to get AP info");
                }
                break;

            default:
                ESP_LOGW(TAG, "UNHANDLED EVENT, event_base: %s, event_id: %ld", event_base, event_id);
                break;
        }
    }
}

esp_err_t wifi_init_sta(void)
{
    esp_err_t ret = ESP_FAIL;
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = ESP_WIFI_SSID,
            .password = ESP_WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_OPEN,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start());
    // ESP_ERROR_CHECK(esp_wifi_set_inactive_time(WIFI_IF_STA, 10));
    // ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(20));
    // int8_t max_power = 0;
    // esp_wifi_get_max_tx_power(&max_power);
    // ESP_LOGI(TAG, "Max TX power: %d", max_power);
    // ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));

    // Enable auto-reconnect
    //ESP_ERROR_CHECK(esp_wifi_set_auto_connect(true));

    //ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        //ESP_LOGI(TAG, "connected to ap SSID:%s password:%s", ESP_WIFI_SSID, ESP_WIFI_PASS);
        output_app();
        ESP_LOGI(TAG, "Wifi connected successfully.");
        ret = ESP_OK;
        return ret;
    } else if (bits & WIFI_FAIL_BIT) {
        //ESP_LOGE(TAG, "Failed to connect to SSID:%s, password:%s", ESP_WIFI_SSID, ESP_WIFI_PASS);
        ESP_LOGE(TAG, "Maximum retries reached. Restarting...");
        esp_restart();
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
    return ret;
}

esp_err_t wifi_main(void)
{
    esp_err_t ret;

    //Initialize NVS
    // ret = nvs_flash_init();
    // if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    //   ESP_ERROR_CHECK(nvs_flash_erase());
    //   ret = nvs_flash_init();
    // }
    // ESP_ERROR_CHECK(ret);
    // ESP_LOGI(TAG, "NVS initialized successfully.");

    //ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");

    uint8_t mac[6];
    ret = esp_wifi_get_mac(WIFI_IF_STA, mac);
    ESP_LOGI(TAG, "Esp MAC: %s" , mac2str(mac));

    if(wifi_init_sta() == ESP_OK) {
        ret = ESP_OK;
        return ret;
    }
    return ret;
}

void wifi_task(void *arg) {

    // Proceed with Wi-Fi initialization and connection
    while (wifi_main() != ESP_OK) {
        ESP_LOGI(TAG, "Retrying Wi-Fi connection...");
        vTaskDelay(pdMS_TO_TICKS(1000));  // Wait for 1 second before retrying
    }

    // // Check if there is certs and keys in NVS
    // ESP_LOGI(TAG, "Checking if certs and keys exist in NVS...");
    // esp_err_t err = check_certs_and_keys_exist();
    // if (err != ESP_OK) {
    //     ESP_LOGI(TAG, "Certs and keys not found in NVS. Proceeding to retrieve them.");
    //     while (http_provision_service() != ESP_OK) {
    //         ESP_LOGI(TAG, "Retrying HTTP connection...");
    //         vTaskDelay(pdMS_TO_TICKS(5000));  // Wait for 5 second before retrying
    //     }
    // } else {
    //     ESP_LOGI(TAG, "Certs and keys found in NVS. Proceeding to MQTT connection.");
    //     while (mqtt_service() != ESP_OK) {
    //         ESP_LOGI(TAG, "Retrying MQTT connection...");
    //         vTaskDelay(pdMS_TO_TICKS(5000));  // Wait for 5 second before retrying
    //     }
    // }


    // Call the MQTT service to connect to the broker
    ESP_LOGI(TAG, "Connecting to MQTT broker...");
    while (mqtt_service() != ESP_OK) {
        ESP_LOGI(TAG, "Retrying MQTT connection...");
        vTaskDelay(pdMS_TO_TICKS(5000));  // Wait for 5 seconds before retrying
    }


    

    ESP_LOGI(TAG, "Wifi task remaining stack: %d bytes", uxTaskGetStackHighWaterMark(NULL));
    for (;;) {
        vTaskDelay(1);
    }
}

esp_err_t wifi_service(void) {
    BaseType_t xReturned;
    xReturned = xTaskCreate(wifi_task, "wifi_task", 3 * 1024, NULL, 10, NULL);
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create Wi-Fi task");
        return ESP_FAIL;
    }
    return ESP_OK;
}
