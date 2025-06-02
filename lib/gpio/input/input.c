#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "output.h"
#include "input.h"

static const char *TAG = "ESP32_INPUT";

#define ESP_INTR_FLAG_DEFAULT 0

//zero-initialize the config structure.
gpio_config_t io_conf = {};

//define the queue for getting input from the ISR
static QueueHandle_t gpio_evt_queue = NULL;

//define callback function
static input_callback_t input_callback = NULL;

//led state
static uint8_t output_led_state = 0;

void isr_handler(void* arg) {
    uint32_t gpio_num = (uint32_t)arg;
    if (input_callback != NULL) {
        input_callback(gpio_num);  // Call the callback only if it is not NULL
    } else {
        // Do nothing
    }
}

void input_set_callback(void *cb) {
    input_callback = cb;
}

void input_set_queue(uint32_t gpio_number) {
    xQueueSendFromISR(gpio_evt_queue, &gpio_number, NULL);
}

void input_configure(int gpio, gpio_int_type_t intr_type) {

    //interrupt of rising edge
    io_conf.intr_type = intr_type;

    //bit mask of the pins
    io_conf.pin_bit_mask = (1ULL << gpio);

    //set as input mode
    io_conf.mode = GPIO_MODE_INPUT;

    //disable pull-up mode
    io_conf.pull_up_en = false;

    //enable pull-down mode
    io_conf.pull_down_en = true;

    //configure GPIO with the given settings
    gpio_config(&io_conf);

    //create a queue to handle gpio event from isr
    gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));

    //install gpio isr service
    gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);

    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(gpio, isr_handler, (void*) gpio);
}
// void input_task(void *arg) {
//     uint32_t io_num;
//     for (;;) {
//         if (xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
//             if (output_led_state == 0) {
//                 ESP_LOGI(TAG, "GPIO[%"PRIu32"] ON!", io_num);
//                 gpio_set_level(2, 1);
//             }
//             else if (output_led_state == 1) {
//                 ESP_LOGI(TAG, "GPIO[%"PRIu32"] OFF!", io_num);
//                 gpio_set_level(2, 0);
//             }
//             output_led_state = !output_led_state;
//         }
//     }
// }


void input_task(void *arg) {
    uint32_t level;
    for (;;) {
        if (xQueueReceive(gpio_evt_queue, &level, portMAX_DELAY)) {
            if (level == 0) {
                ESP_LOGI(TAG, "GPIO[%"PRIu32"] LOW!", level);
            } else if (level == 1) {
                ESP_LOGI(TAG, "GPIO[%"PRIu32"] HIGH!", level);
            }
        }
    }
}

void input_app(void) {
    //input_configure(INPUT_GPIO_DEFAULT, GPIO_INTR_POSEDGE);
    input_configure(INPUT_GPIO_BOOT, GPIO_INTR_ANYEDGE); //GPIO_INTR_DISABLE
    //output_configure(2);

    xTaskCreate(input_task, "input_task", 2048, NULL, 6, NULL);
}