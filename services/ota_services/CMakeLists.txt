set(app_src ota_services.c)

set(pri_req lwip esp_http_client app_update esp_partition mbedtls http_services mqtt_services tuya)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})