set(app_src input.c)

set(pri_req driver output)
idf_component_register(SRCS ${app_src}
                       INCLUDE_DIRS "." 
                       REQUIRES ${pri_req})