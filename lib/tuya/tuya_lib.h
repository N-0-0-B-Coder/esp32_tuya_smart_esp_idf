#ifndef __TUYA_LIB_H__
#define __TUYA_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include "cJSON.h"
#include "mqtt_client.h"

typedef enum {
    THING_TYPE_MODEL_GET,
    THING_TYPE_MODEL_RSP,
    THING_TYPE_PROPERTY_REPORT,
    THING_TYPE_PROPERTY_REPORT_RSP,
    THING_TYPE_PROPERTY_SET,
    THING_TYPE_PROPERTY_SET_RSP,
    THING_TYPE_PROPERTY_DESIRED_GET,
    THING_TYPE_PROPERTY_DESIRED_GET_RSP,
    THING_TYPE_PROPERTY_DESIRED_DEL,
    THING_TYPE_PROPERTY_DESIRED_DEL_RSP,
    THING_TYPE_EVENT_TRIGGER,
    THING_TYPE_EVENT_TRIGGER_RSP,
    THING_TYPE_ACTION_EXECUTE,
    THING_TYPE_ACTION_EXECUTE_RSP,
    THING_TYPE_BATCH_REPORT,
    THING_TYPE_BATCH_REPORT_RSP,
    THING_TYPE_DEVICE_SUB_BIND,
    THING_TYPE_DEVICE_SUB_BIND_RSP,
    THING_TYPE_DEVICE_SUB_LOGIN,
    THING_TYPE_DEVICE_SUB_LOGOUT,
    THING_TYPE_DEVICE_TOPO_ADD,
    THING_TYPE_DEVICE_TOPO_ADD_RSP,
    THING_TYPE_DEVICE_TOPO_DEL,
    THING_TYPE_DEVICE_TOPO_DEL_RSP,
    THING_TYPE_DEVICE_TOPO_GET,
    THING_TYPE_DEVICE_TOPO_GET_RSP,
    THING_TYPE_OTA_FIRMWARE_REPORT,
    THING_TYPE_OTA_ISSUE,
    THING_TYPE_OTA_GET,
    THING_TYPE_OTA_GET_RSP,
    THING_TYPE_OTA_PROGRESS_REPORT,
    THING_TYPE_EXT_TIME_REQUEST,
    THING_TYPE_EXT_TIME_RESPONSE,
    THING_TYPE_EXT_CONFIG_GET,
    THING_TYPE_EXT_CONFIG_GET_RSP,
    THING_TYPE_EXT_FILE_UPLOAD_REQUEST,
    THING_TYPE_EXT_FILE_UPLOAD_RESPONSE,
    THING_TYPE_EXT_FILE_DOWNLOAD_REQUEST,
    THING_TYPE_EXT_FILE_DOWNLOAD_RESPONSE,
    THING_TYPE_CHANNEL_RAW_UP,
    THING_TYPE_CHANNEL_RAW_DOWN,
    THING_TYPE_CHANNEL_RPC_REQUEST,
    THING_TYPE_CHANNEL_RPC_RESPONSE,
    THING_TYPE_DEVICE_TAG_REPORT,
    THING_TYPE_DEVICE_TAG_REPORT_RESPONSE,
    THING_TYPE_DEVICE_TAG_GET,
    THING_TYPE_DEVICE_TAG_GET_RESPONSE,
    THING_TYPE_DEVICE_TAG_DELETE,
    THING_TYPE_DEVICE_TAG_DELETE_RESPONSE,
    THING_TYPE_MAX,
    THING_TYPE_UNKNOWN,
} tuyalink_thing_type_t;

typedef struct {
    tuyalink_thing_type_t type;
    char*    device_id;
    char*    msgid;
    uint64_t time;
    uint32_t code;
    cJSON*   data_json;
    char*    data_string;
    bool     ack;
} tuyalink_message_t;

#define TOPIC_LEN_MAX (128)

int tuya_mqtt_auth_signature_calculate(const char* deviceId, const char* deviceSecret,
									   char* clientID, char* username, char* password);

int tuya_subcribe(esp_mqtt_client_handle_t client, const char *deviceId, int qos);

int tuya_message_send(esp_mqtt_client_handle_t client, const char *deviceId, tuyalink_message_t* message);

#ifdef __cplusplus
}
#endif

#endif // __TUYA_LIB_H__
