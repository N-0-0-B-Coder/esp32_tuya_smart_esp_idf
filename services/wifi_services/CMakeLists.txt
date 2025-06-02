set(app_src wifi_services.c)

set(pri_req esp_wifi nvs_flash mqtt http_services mqtt_services output)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})