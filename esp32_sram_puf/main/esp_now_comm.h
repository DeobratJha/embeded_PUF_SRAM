#ifndef ESP_NOW_COMM_H
#define ESP_NOW_COMM_H

#define MSG_KYBER_PK_OFFER    10
#define MSG_KYBER_CT_RESPONSE 11

#include "esp_now.h"
#include "esp_wifi.h"
#include "authentication.h"
#define max_uavs 10
typedef enum {
    MSG_CHALLENGE = 1,
    MSG_RESPONSE = 2,
    MSG_AUTH_SUCCESS = 3,
    MSG_AUTH_FAILED = 4
} msg_type_t;


#define ESPNOW_MAX_DATA_LEN 1600   // Supports Kyber payloads

typedef struct {
    msg_type_t type;
    uint16_t data_len;
    uint8_t data[ESPNOW_MAX_DATA_LEN];
} espnow_message_t;

esp_err_t espnow_init(bool is_gcc);
esp_err_t espnow_send_message(const uint8_t *peer_addr, espnow_message_t *msg);
void espnow_set_recv_callback(void (*callback)(const uint8_t *mac, const uint8_t *data, int len));

// Update these with your actual MAC addresses
extern uint8_t gcc_mac[6];
extern uint8_t uav_mac[max_uavs][6];

#endif
