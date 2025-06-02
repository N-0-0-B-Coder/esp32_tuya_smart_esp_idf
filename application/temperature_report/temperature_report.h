#ifndef __TEMPERATURE_REPORT_H__
#define __TEMPERATURE_REPORT_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define TUYA_MQTT

int get_temperature(void);
void tuya_temperature_report(void);

#endif // __TEMPERATURE_REPORT_H__
