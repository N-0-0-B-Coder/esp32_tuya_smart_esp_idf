#include "humidity_report.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"


int humidity = 0;

#ifdef TUYA_MQTT

int get_humidity(void) {
    return humidity;
}

void humidity_data_task(void *arg) {
    for (;;) {
        humidity = rand() % 101;

        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

void tuya_humidity_report(void) {
    // Create a task to generate humidity data
    xTaskCreate(humidity_data_task, "humidity_data_task", 1024, NULL, 4, NULL);
}

#endif