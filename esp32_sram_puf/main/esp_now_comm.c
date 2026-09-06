#include "esp_now_comm.h"
#include "esp_log.h"
#include "string.h"
#define max_uavs 10

static const char* TAG = "ESP_NOW";

// TODO: Update these with actual MAC addresses from your ESP32s
uint8_t gcc_mac[6] = {0xB0, 0xCB, 0xD8, 0xC8, 0xBE, 0x80};//{0x24, 0x6F, 0x28, 0x00, 0x00, 0x01};  // Replace with GCC MAC
uint8_t uav_mac[max_uavs][6] = {{0xB0, 0xCB, 0xD8, 0xC9, 0x0B, 0x18}};//{0x24, 0x6F, 0x28, 0x00, 0x00, 0x02};  // Replace with UAV MAC

static void (*user_recv_cb)(const uint8_t *, const uint8_t *, int) = NULL;

static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
    if (user_recv_cb) {
        user_recv_cb(recv_info->src_addr, data, len);
    }
}

esp_err_t espnow_init(bool is_gcc) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
    
    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(esp_now_peer_info_t));
    peer.channel = 0;
    peer.encrypt = false;
    
    if (is_gcc) {
        memcpy(peer.peer_addr, uav_mac, 6);
        ESP_LOGI(TAG, "GCC mode initialized");
    } else {
        memcpy(peer.peer_addr, gcc_mac, 6);
        ESP_LOGI(TAG, "UAV mode initialized");
    }
    
    ESP_ERROR_CHECK(esp_now_add_peer(&peer));
    return ESP_OK;
}

// esp_err_t espnow_send_message(const uint8_t *peer_addr, espnow_message_t *msg) {
//     return esp_now_send(peer_addr, (uint8_t*)msg, sizeof(espnow_message_t));
// }

esp_err_t espnow_send_message(const uint8_t *peer_addr, espnow_message_t *msg) {
    size_t total_len = sizeof(msg->type) + sizeof(msg->data_len) + msg->data_len;
    if (msg->data_len > ESPNOW_MAX_DATA_LEN) {
        ESP_LOGE("ESP_NOW", "Data length %d exceeds max (%d)", msg->data_len, ESPNOW_MAX_DATA_LEN);
        return ESP_FAIL;
    }
    return esp_now_send(peer_addr, (uint8_t *)msg, total_len);
}


void espnow_set_recv_callback(void (*callback)(const uint8_t *mac, const uint8_t *data, int len)) {
    user_recv_cb = callback;
}
