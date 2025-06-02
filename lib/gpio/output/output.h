#ifndef __OUTPUT_H
#define __OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define BLINK_GPIO_DEFAULT 2

void blink_led(int gpio);
void output_configure(int gpio);
//void output_task(void* arg);
void output_app(void);

#ifdef __cplusplus
}
#endif

#endif // __OUTPUT_H


