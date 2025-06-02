set(app_src temperature_report.c)

set(pri_req mbedtls mqtt json)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})