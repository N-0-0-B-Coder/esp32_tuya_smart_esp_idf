#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "mbedtls/md.h"

#include "esp_sntp.h"
#include "esp_log.h"
#include "esp_err.h"

#include "tuya_lib.h"

static const char *TAG = "TUYA_LIB";

const char tylink_suffix_map[][48] = {
	"thing/model/get",
	"thing/model/get_response", // subscribe 1
	"thing/property/report",
	"thing/property/report_response", // subscribe 3
	"thing/property/set", // subscribe 4
	"thing/property/set_response",
	"thing/property/desired/get",
	"thing/property/desired/get_response", // subscribe 7
	"thing/property/desired/delete",
	"thing/property/desired/delete_response", // subscribe 9
	"thing/event/trigger",
	"thing/event/trigger_response", // subscribe 11
	"thing/action/execute", // subscribe 12
	"thing/action/execute_response",
	"thing/data/batch_report",
	"thing/data/batch_report_response", // subscribe 15
	"device/sub/bind",
	"device/sub/bind_response", // subscribe 17
	"device/sub/login",
	"device/sub/logout",
	"device/topo/add",
	"device/topo/add_response", // subscribe 21
	"device/topo/delete",
	"device/topo/delete_response", // subscribe 23
	"device/topo/get",
	"device/topo/get_response", // subscribe 25
	"ota/firmware/report",
	"ota/issue", // subscribe 27
	"ota/get",
	"ota/get_response", // subscribe 29
	"ota/progress/report",
	"ext/time/request",
	"ext/time/response", // subscribe 32
	"ext/file/upload/request",
	"ext/file/upload/response", // subscribe 34
	"ext/file/download/request",
	"ext/file/download/response", // subscribe 36
	"ext/config/get",
	"ext/config/get_response", // subscribe 38
	"channel/raw/up",
	"channel/raw/down", // subscribe 40
	"channel/rpc/request",
	"channel/rpc/response", // subscribe 42
	"device/tag/report",
	"device/tag/report_response", // subscribe 44
	"device/tag/get",
	"device/tag/get_response", // subscribe 46
	"device/tag/delete",
	"device/tag/delete_response", // subscribe 48
};

static int mbedtls_message_digest_hmac(mbedtls_md_type_t md_type,
                                const uint8_t* key, size_t keylen,
                                const uint8_t* input, size_t ilen, 
                                uint8_t* digest)
    {
    if (key == NULL || keylen == 0 || input == NULL || ilen == 0 || digest == NULL) return -1;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    int ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_md_hmac_starts(&md_ctx, key, keylen);
    mbedtls_md_hmac_update(&md_ctx, input, ilen);
    mbedtls_md_hmac_finish(&md_ctx, digest);

exit:
    mbedtls_md_free(&md_ctx);
    return ret;
}

static int hmac_sha256_once(const uint8_t* key, const uint8_t* input, size_t ilen, uint8_t* digest)
{
    return mbedtls_message_digest_hmac(MBEDTLS_MD_SHA256, key, 16, input, ilen, digest);
}

int tuya_mqtt_auth_signature_calculate(const char* deviceId, const char* deviceSecret,
											  char* clientID, char* username, char* password)
{
    if (NULL == deviceId || NULL == deviceSecret) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t timestamp = time(NULL); // Get current timestamp in seconds
    ESP_LOGD(TAG, "Current timestamp: %ld", timestamp);

    /* username */
    sprintf(username, "%s|signMethod=hmacSha256,timestamp=%ld,secureMode=1,accessType=1", deviceId, timestamp);
    ESP_LOGD(TAG, "username:%s", username);

    /* client ID */
    sprintf(clientID, "tuyalink_%s", deviceId);
    ESP_LOGD(TAG, "clientID:%s", clientID);

    /* password */
    int i = 0;
    char passward_stuff[255];
    uint8_t digest[32];
    size_t slen = sprintf(passward_stuff, "deviceId=%s,timestamp=%ld,secureMode=1,accessType=1", deviceId, timestamp);
    hmac_sha256_once((uint8_t *)deviceSecret, (uint8_t *)passward_stuff, slen, digest);
    for (i = 0; i < 32; i++) {
        sprintf(password + 2*i, "%02x", digest[i]);
    }
    ESP_LOGD(TAG, "password:%s", password);

    return ESP_OK;
}

int tuya_subcribe(esp_mqtt_client_handle_t client, const char *deviceId, int qos) {
    int msg_id;

    if (client == NULL) {
        ESP_LOGE(TAG, "Invalid MQTT client handle");
        return ESP_ERR_INVALID_ARG;
    }

    char topic_stuff[TOPIC_LEN_MAX];

    for (int i = 0; i < 49; i++) {
        if (i == 0 || i == 2 || i == 5 || i == 6 || i == 8 || i == 10 || i == 13 || i == 14 ||
            i == 16 || i == 18 || i == 19 || i == 20 || i == 22 || i == 24 || i == 26 || i == 28 || i == 30 || i == 31 ||
            i == 33 || i == 35 || i == 37 || i == 39 || i == 41 || i == 43 || i == 45 || i == 47) {
            continue; // Skip publish topics
        }
        snprintf(topic_stuff, TOPIC_LEN_MAX, "tylink/%s/%s", deviceId, tylink_suffix_map[i]);
        msg_id = esp_mqtt_client_subscribe(client, topic_stuff, qos);
        if (msg_id < 0) {
            ESP_LOGE(TAG, "Failed to subscribe to topic %s, error code: %d", topic_stuff, msg_id);
            return msg_id;
        } else {
            ESP_LOGI(TAG, "Subscribe sent with topic %s successful, msg_id=%d", topic_stuff, msg_id);
        }
    }

    return ESP_OK;
}


int tuya_message_send(esp_mqtt_client_handle_t client, const char *deviceId, tuyalink_message_t* message) {
    if (client == NULL || message == NULL) {
        ESP_LOGE(TAG, "Invalid parameters for tuyalink_message_send");
        return ESP_ERR_INVALID_ARG;
    }

    /* Device ID */
    char* device_id = (message->device_id ? message->device_id : deviceId);

    /* Topic */
    char topic_stuff[TOPIC_LEN_MAX];
    snprintf(topic_stuff, TOPIC_LEN_MAX, "tylink/%s/%s", device_id, tylink_suffix_map[message->type]);

    /* Make payload */
    size_t payload_length = 0;
    uint32_t msgid_int = 0;
    size_t alloc_size = 128;
    if (message->data_string) {
        alloc_size += strlen(message->data_string);
    }
    char* payload = malloc(alloc_size);
    if (payload == NULL) {
        ESP_LOGE(TAG, "Memory allocation failed for payload");
        return ESP_ERR_NO_MEM;
    }

    /* JSON start  */
    payload_length = snprintf(payload, alloc_size, "{");

    /* msgId */
    if (message->msgid && message->msgid[0] != 0) {
        payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
            "\"msgId\":\"%s\"", message->msgid);
    } else {
        msgid_int = (int)time(NULL); // Use timestamp as msgId
        payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
            "\"msgId\":\"%ld\"", msgid_int);
    }

    /* time */
    if (message->time) {
        payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
            ",\"time\":%d", (int)message->time);
    } else {
        payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
            ",\"time\":%d", (int)time(NULL));
    }

    /* data */
    if (message->data_string && message->data_string[0] != 0) {
        payload_length += snprintf(payload + payload_length, alloc_size - payload_length,
            ",\"data\":%s", message->data_string);
    }

    /* End JSON */
    payload_length += snprintf(payload + payload_length, alloc_size - payload_length, "}");

    ESP_LOGI(TAG, "Payload content: %s", payload);
    // Publish the message
    int msg_id = esp_mqtt_client_publish(client, topic_stuff, payload, payload_length, 1, 0);
    if (msg_id < 0) {
        ESP_LOGE(TAG, "Failed to publish message to topic %s, error code: %d", topic_stuff, msg_id);
        free(payload);
        return msg_id;
    } else {
        ESP_LOGI(TAG, "Publish sent with topic %s successful, msg_id=%d", topic_stuff, msg_id);
    }

    free(payload);
    return ESP_OK;
}