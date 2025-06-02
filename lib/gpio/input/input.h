#ifndef __INPUT_H
#define __INPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "driver/gpio.h"

#define INPUT_GPIO_DEFAULT 3
#define INPUT_GPIO_BOOT 0

typedef void (*input_callback_t)(uint32_t gpio_num);

void input_configure(int gpio, gpio_int_type_t intr_type);
void input_set_callback(void *cb);
void input_set_queue(uint32_t gpio_number);
void input_task(void* arg);
void input_app(void);


#ifdef __cplusplus
}
#endif

#endif // __INPUT_H