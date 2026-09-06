/* File 3: main/authentication.h */
#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "mbedtls/sha256.h"
#include "esp_timer.h"


#define CHALLENGE_SIZE 32
#define RESPONSE_SIZE 32
#define DEVICE_ID_SIZE 16
#define MSG_KYBER_PK_OFFER    10
#define MSG_KYBER_CT_RESPONSE 11

typedef struct {
    uint8_t device_id[DEVICE_ID_SIZE];
    uint8_t challenge[CHALLENGE_SIZE];
    uint8_t response[RESPONSE_SIZE];
    uint32_t timestamp;
} auth_message_t;

typedef enum {
    AUTH_SUCCESS = 0,
    AUTH_ERROR = 1
} auth_result_t;

////////obj - 2/////////////
typedef enum {
    KYBER_STATE_IDLE = 0,
    KYBER_STATE_PK_SENT = 1,
    KYBER_STATE_CT_RECEIVED = 2,
    KYBER_STATE_SESSION_READY = 3
} kyber_session_state_t;
/////////////////

esp_err_t auth_init(void);
auth_result_t authenticate_device(auth_message_t* auth_msg);
void generate_random_challenge(uint8_t* challenge);
bool verify_response(auth_message_t* auth_msg);


int enroll_new_uav(const uint8_t *mac, const uint8_t *helper_data);
int deactivate_uav(const uint8_t *mac);
void print_enrolled_uavs(void);

void auth_worker_task(void *pv);
extern volatile bool auth_task_running;

#endif