#ifndef __HUMIDITY_REPORT_H__
#define __HUMIDITY_REPORT_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define TUYA_MQTT

int get_humidity(void);
void tuya_humidity_report(void);

#endif // __HUMIDITY_REPORT_H__
