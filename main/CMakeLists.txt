idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES output input wifi_services http_services mqtt_services temperature_report humidity_report)