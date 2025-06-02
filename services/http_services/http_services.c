#include "http_services.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "cJSON.h"
#include "nvs_flash.h"

#include "esp_partition.h"
#include "esp_ota_ops.h"

#include "mqtt_services.h"

static const char *TAG = "ESP32_HTTP";

static char *http_root_ca = NULL,
     *http_device_cert = NULL,
     *http_private_key = NULL,
     *http_public_key = NULL;

static bool cert_ok = false;


void get_cert(char **out_root_ca, char **out_device_cert, char **out_private_key) {
    ESP_LOGI(TAG, "HTTP Root CA: %s", http_root_ca ? http_root_ca : "NULL");
    ESP_LOGI(TAG, "HTTP Device Certificate: %s", http_device_cert ? http_device_cert : "NULL");
    ESP_LOGI(TAG, "HTTP Private Key: %s", http_private_key ? http_private_key : "NULL");
    if (out_root_ca) {
        *out_root_ca = http_root_ca;  // Assign the global variable to the caller's pointer
    }
    if (out_device_cert) {
        *out_device_cert = http_device_cert;
    }
    if (out_private_key) {
        *out_private_key = http_private_key;
    }
}

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

esp_err_t retrieve_certs_and_keys(char **out_root_ca, char **out_device_cert, char **out_private_key) {
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

    err = get_string_from_nvs(nvs_handle, "device_cert", out_device_cert);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve device_cert");
    }

    err = get_string_from_nvs(nvs_handle, "private_key", out_private_key);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve private_key");
    }

    // Close the NVS handle
    nvs_close(nvs_handle);
    return ESP_OK;
}


static esp_err_t check_key_exists(nvs_handle_t nvs_handle, const char *key) {
    size_t required_size = 0;
    esp_err_t err = nvs_get_str(nvs_handle, key, NULL, &required_size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Key '%s' not found in NVS", key);
        return ESP_ERR_NVS_NOT_FOUND;
    } else if (required_size == 0) {
        ESP_LOGW(TAG, "Key '%s' exists but has no value", key);
        return ESP_FAIL;
    } else {
        ESP_LOGI(TAG, "Key '%s' exists with size %d", key, required_size);
    }
    return ESP_OK;
}

esp_err_t check_certs_and_keys_exist() {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    // Open NVS storage with the same namespace (e.g., "certs")
    err = nvs_open("certs", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    // Check each certificate/key
    if ((err = check_key_exists(nvs_handle, "root_ca")) != ESP_OK) {
        ESP_LOGW(TAG, "Missing root_ca in NVS");
        nvs_close(nvs_handle);
        return err;
    }
    if ((err = check_key_exists(nvs_handle, "device_cert")) != ESP_OK) {
        ESP_LOGW(TAG, "Missing device_cert in NVS");
        nvs_close(nvs_handle);
        return err;
    }
    if ((err = check_key_exists(nvs_handle, "private_key")) != ESP_OK) {
        ESP_LOGW(TAG, "Missing private_key in NVS");
        nvs_close(nvs_handle);
        return err;
    }

    // Close the NVS handle
    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "All certificates and keys exist in NVS");
    return ESP_OK;
}

esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    esp_err_t ret = ESP_FAIL;
    static char *response_buffer = NULL;
    static int total_len = 0;

    switch (evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "HTTP_EVENT_ERROR");
            return ret;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADERS_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADERS_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            if (response_buffer == NULL) {
                // Allocate memory for the response buffer based on Content-Length
                int content_length = esp_http_client_get_content_length(evt->client);
                if (content_length > 0) {
                    response_buffer = (char *)malloc(content_length + 1);  // +1 for null-terminator
                    if (response_buffer == NULL) {
                        ESP_LOGE(TAG, "Failed to allocate memory for response buffer");
                        return ret;
                    }
                    total_len = 0;  // Reset total length
                } else {
                    ESP_LOGE(TAG, "Invalid Content-Length: %d", content_length);
                    return ret;
                }
            }

            // Copy response data into buffer
            if (total_len + evt->data_len <= esp_http_client_get_content_length(evt->client)) {
                memcpy(response_buffer + total_len, evt->data, evt->data_len);
                total_len += evt->data_len;
                response_buffer[total_len] = '\0';  // Null-terminate
            } else {
                ESP_LOGE(TAG, "Response buffer overflow");
                free(response_buffer);
                response_buffer = NULL;
                return ret;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            //ESP_LOGI(TAG, "HTTP Response: %s", response_buffer);
            
            // Parse JSON
            cJSON *root = cJSON_Parse(response_buffer);
            if (root == NULL) {
                ESP_LOGE(TAG, "JSON Parsing Failed!");
                return ret;
            }

            // Extract values
            http_root_ca = cJSON_GetObjectItem(root, "root_ca")->valuestring;
            http_device_cert = cJSON_GetObjectItem(root, "device_cert")->valuestring;
            http_private_key = cJSON_GetObjectItem(root, "private_key")->valuestring;
            http_public_key = cJSON_GetObjectItem(root, "public_key")->valuestring;

            if (http_root_ca && http_device_cert && http_private_key && http_public_key) {

                // Create a mutex for thread safety
                static SemaphoreHandle_t nvs_mutex = NULL;
                if (nvs_mutex == NULL) {
                    nvs_mutex = xSemaphoreCreateMutex();
                    if (nvs_mutex == NULL) {
                        ESP_LOGE(TAG, "Failed to create NVS mutex");
                        return ESP_ERR_NO_MEM;
                    }
                }

                // Take the mutex before accessing NVS
                if (xSemaphoreTake(nvs_mutex, portMAX_DELAY) == pdTRUE) {
                    // Open NVS storage with a namespace
                    nvs_handle_t nvs_handle;
                    esp_err_t err = nvs_open("certs", NVS_READWRITE, &nvs_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to open NVS handle: %s", esp_err_to_name(err));
                        return err;
                    }

                    // Erase the "certs" namespace before setting new values
                    err = nvs_erase_all(nvs_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to erase NVS namespace: %s", esp_err_to_name(err));
                        nvs_close(nvs_handle);
                        return err;
                    }

                    // Store each certificate/key as a string
                    if (http_root_ca) {
                        err = nvs_set_str(nvs_handle, "root_ca", http_root_ca);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "Failed to store root_ca: %s", esp_err_to_name(err));
                            nvs_close(nvs_handle);
                            return err;
                        }
                    }
                    if (http_device_cert) {
                        err = nvs_set_str(nvs_handle, "device_cert", http_device_cert);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "Failed to store device_cert: %s", esp_err_to_name(err));
                            nvs_close(nvs_handle);
                            return err;
                        }
                    }
                    if (http_private_key) {
                        err = nvs_set_str(nvs_handle, "private_key", http_private_key);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "Failed to store private_key: %s", esp_err_to_name(err));
                            nvs_close(nvs_handle);
                            return err;
                        }
                    }
                    if (http_public_key) {
                        err = nvs_set_str(nvs_handle, "public_key", http_public_key);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "Failed to store public_key: %s", esp_err_to_name(err));
                            nvs_close(nvs_handle);
                            return err;
                        }
                    }

                    // Commit the changes to NVS
                    err = nvs_commit(nvs_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to commit changes to NVS: %s", esp_err_to_name(err));
                    }

                    // Close the NVS handle
                    nvs_close(nvs_handle);

                    // Release the mutex after accessing NVS
                    xSemaphoreGive(nvs_mutex);
                } else {
                    ESP_LOGE(TAG, "Failed to take NVS mutex");
                    return ESP_FAIL;
                }


                //ESP_LOGI(TAG, "HTTP Root CA:\n\"%d\"", strlen(http_root_ca));
                //ESP_LOGI(TAG, "HTTP Device Certificate:\n\"%d\"", strlen(http_device_cert));
                //ESP_LOGI(TAG, "HTTP Private Key:\n\"%d\"", strlen(http_private_key));
                // ESP_LOGI(TAG, "Public Key:\n\"%s\"", http_public_key);
                cert_ok = true;
            } else {
                ESP_LOGE(TAG, "Missing fields in JSON response!");
            }

            // Clean up JSON object
            cJSON_Delete(root);

            // Free the response buffer
            free(response_buffer);
            response_buffer = NULL;

            // Reset buffer
            total_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;

        default:
            ESP_LOGI(TAG, "HTTP_EVENT_UNKNOWN");
            break;
    }
    return ESP_OK;
}


esp_err_t https_request(char *type) {
    esp_err_t ret = ESP_FAIL;
    char path[20];
    snprintf(path, sizeof(path), "/%s", type);

    char full_url[256];
    snprintf(full_url, sizeof(full_url), "%s%s", AWS_API_URL, path);
    ESP_LOGI(TAG, "Full URL: %s", full_url);

    esp_http_client_config_t config = {
        .url = full_url,
        .cert_pem = ROOT_CA_CERTIFICATE,
        .port = 443,
        .event_handler = _http_event_handler,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);

    // Set headers
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    // Set request body
    char *device_id = "ESP32-001";
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return ret;
    }

    cJSON_AddStringToObject(json, "device_id", device_id);

    char *request_body = cJSON_PrintUnformatted(json);
    if (request_body == NULL) {
        ESP_LOGE(TAG, "Failed to print JSON object");
        cJSON_Delete(json);
        return ret;
    }

    cJSON_Delete(json); 
    esp_http_client_set_post_field(client, request_body, strlen(request_body));

    // Perform the request
    ESP_LOGI(TAG, "Performing HTTPS request to %s, body: %s", path, request_body);
    ret = esp_http_client_perform(client);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, Content Length = %lld",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP Request failed: %s", esp_err_to_name(ret));
    }

    while (cert_ok == false) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    // Cleanup
    esp_http_client_cleanup(client);

    cert_ok = false; // Reset the flag for the next request
    free(request_body); // Free the request body after use
    mqtt_service();
    ESP_LOGI(TAG, "MQTT service started after HTTPS request");

    return ret;
}


void http_task(void *pvParameters) {
    uint8_t count = 0;
    while (https_request("provisioning") != ESP_OK && count < 10) {
        ESP_LOGI(TAG, "Retrying HTTPS request...");
        vTaskDelay(pdMS_TO_TICKS(5000));  // Wait for 5 seconds before retrying
        count++;
    }

    if (count == 10) {
        ESP_LOGE(TAG, "Failed to retrieve certs and keys after 10 attempts.");
    }

    ESP_LOGI(TAG, "HTTP task remaining stack: %d bytes", uxTaskGetStackHighWaterMark(NULL));
    vTaskDelete(NULL);
}

esp_err_t http_provision_service(void) {
    BaseType_t xReturned;
    xReturned = xTaskCreate(http_task, "http_task", 4096, NULL, 9, NULL);
    if (xReturned != pdPASS) {
        ESP_LOGE(TAG, "Failed to create HTTP task");
        return ESP_FAIL;
    }
    return ESP_OK;
}