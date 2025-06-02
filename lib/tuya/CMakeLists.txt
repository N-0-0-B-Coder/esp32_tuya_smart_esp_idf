set(app_src tuya_lib.c)

set(pri_req mbedtls mqtt json)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})