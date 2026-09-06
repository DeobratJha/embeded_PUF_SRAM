#include "distance_sensor.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "rom/ets_sys.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"  // ★ ADD THIS


static const char* TAG = "DISTANCE";

esp_err_t distance_sensor_init(void) {
    gpio_config_t trig_conf = {
        .pin_bit_mask = (1ULL << TRIG_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&trig_conf);
    
    gpio_config_t echo_conf = {
        .pin_bit_mask = (1ULL << ECHO_PIN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&echo_conf);
    
    gpio_set_level(TRIG_PIN, 0);
    ESP_LOGI(TAG, "Distance sensor initialized");
    return ESP_OK;
}

float get_distance_cm(void) {

    // ★ Add watchdog reset at start
    //esp_task_wdt_reset();


    gpio_set_level(TRIG_PIN, 1);
    ets_delay_us(10);
    gpio_set_level(TRIG_PIN, 0);
    
     // ★ Add watchdog reset before wait
    //esp_task_wdt_reset();

    int timeout = 10000;
    while (gpio_get_level(ECHO_PIN) == 0 && timeout-- > 0) {
        ets_delay_us(1);
    }

     // ★ Add watchdog reset after wait
    //esp_task_wdt_reset();


    if (timeout <= 0) return -1.0;
    
    int64_t start = esp_timer_get_time();
    timeout = 30000;
    
    while (gpio_get_level(ECHO_PIN) == 1 && timeout-- > 0) {
        ets_delay_us(1);
    }
    
    int64_t end = esp_timer_get_time();
    int64_t duration_us = end - start;
    
    float distance = duration_us / 58.0;
    return (distance > 0 && distance < 400) ? distance : -1.0;
}

bool is_uav_in_range(void) {
    static bool last_in_range = false;
    float dist = get_distance_cm();
    bool currently_in_range = (dist > 0 && dist <= DETECTION_THRESHOLD_CM);
    
    // Only log on state change
    if (currently_in_range && !last_in_range) {
        ESP_LOGI(TAG, "UAV detected at %.1f cm", dist);
    } else if (!currently_in_range && last_in_range) {
        ESP_LOGI(TAG, "UAV left detection range");
    }
    
    last_in_range = currently_in_range;
    return currently_in_range;
}
