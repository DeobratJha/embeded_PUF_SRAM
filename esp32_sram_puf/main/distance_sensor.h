#ifndef DISTANCE_SENSOR_H
#define DISTANCE_SENSOR_H
//#include "esp_timer.h"

#include "esp_err.h"
#include <stdbool.h>

#define TRIG_PIN 12
#define ECHO_PIN 14
#define DETECTION_THRESHOLD_CM 100  // UAV detected within 100cm

esp_err_t distance_sensor_init(void);
float get_distance_cm(void);
bool is_uav_in_range(void);

#endif
