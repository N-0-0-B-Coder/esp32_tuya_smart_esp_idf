#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "output.h"

static const char *TAG = "output";

static uint8_t output_led_state = 0;

void blink_led(int gpio)
{
    /* Set the GPIO level according to the state (LOW or HIGH)*/
    gpio_set_level(BLINK_GPIO_DEFAULT, output_led_state);
}

#ifdef CONFIG_IDF_SIMPLE_GPIO_SET_UP
void output_configure(void)
{
    //ESP_LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_reset_pin(BLINK_GPIO_DEFAULT);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(BLINK_GPIO_DEFAULT, GPIO_MODE_OUTPUT);
}
#else
void output_configure(int gpio)
{
    //ESP_LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_config_t io_conf;
    //disable interrupt
    io_conf.intr_type = GPIO_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = (1ULL << gpio);
    //disable pull-down mode
    io_conf.pull_down_en = 0;
    //disable pull-up mode
    io_conf.pull_up_en = 1;
    //configure GPIO with the given settings
    gpio_config(&io_conf);
}
#endif


void output_task(void* arg) {
    /* Configure the peripheral according to the LED type */
    output_configure(BLINK_GPIO_DEFAULT);

    gpio_set_level(BLINK_GPIO_DEFAULT, 1);

    for (;;) {
        vTaskDelay(1);
    }
}

void output_app(void)
{
    xTaskCreate(output_task, "output_task", 2048, NULL, 7, NULL);
}