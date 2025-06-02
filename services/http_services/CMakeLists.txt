set(app_src http_services.c)

set(pri_req lwip esp_http_client esp_http_server esp_wifi nvs_flash json mqtt_services app_update)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})