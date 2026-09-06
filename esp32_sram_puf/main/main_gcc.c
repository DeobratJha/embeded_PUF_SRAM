#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"           // ★ ADD THIS - for response queue
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "puf_lib.h"
#include "authentication.h"
#include "distance_sensor.h"
#include "esp_now_comm.h"
#include "esp_timer.h"
#include "kyber_key_agreement.h"

#define MSG_KYBER_PK_OFFER     10
#define MSG_KYBER_CT_RESPONSE  11


static const char* TAG = "GCC";
volatile bool auth_task_running = false;

typedef enum {
    STATE_IDLE,
    STATE_AUTHENTICATING,
    STATE_AUTHENTICATED
} gcc_state_t;

static gcc_state_t current_state = STATE_IDLE;
static bool uav_authenticated = false;

// ★ ADD THIS - Queue for authentication responses
static QueueHandle_t auth_response_queue = NULL;


/////////////// objective 2
// ---------------------- Kyber Global Variables (GCC) ----------------------
static uint8_t kyber_pk[KYBER_PUBLICKEY_BYTES];
static uint8_t kyber_sk[KYBER_SECRETKEY_BYTES];
static uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
static uint8_t kyber_ss[KYBER_SHAREDSECRET_BYTES];
static kyber_session_t session;

// ISR-safe queue: Pass ciphertext from callback to worker task
typedef struct {
    uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES];
} kyber_ct_item_t;

static QueueHandle_t kyber_ct_queue = NULL;
// --------------------------------------------------------------------------

///////////////////////
// ========================================
// ★ CALLBACK - SIMPLE, NO BLOCKING CALLS
// ========================================
void gcc_recv_callback(const uint8_t *mac, const uint8_t *data, int len) {
    espnow_message_t *msg = (espnow_message_t *)data;
    
    if (msg->type == MSG_RESPONSE) {
        // ★ JUST queue the message - don't process here!
        if (auth_response_queue != NULL) {
            xQueueSendFromISR(auth_response_queue, msg, NULL);
        }
    }

    ////////////// Objective 2
    else if (msg->type == MSG_KYBER_CT_RESPONSE) {
        ESP_LOGI(TAG, "Received Kyber ciphertext from UAV");

        // ISR-SAFE: Just queue the ciphertext, let worker task do decapsulation
        if (kyber_ct_queue != NULL) {
            kyber_ct_item_t ct_item;
            memcpy(ct_item.ciphertext, msg->data, KYBER_CIPHERTEXT_BYTES);
            
            BaseType_t higher_priority_task_woken = pdFALSE;
            xQueueSendFromISR(kyber_ct_queue, &ct_item, &higher_priority_task_woken);
            if (higher_priority_task_woken) {
                portYIELD_FROM_ISR();
            }
        }
    }

}

// ============================================================================
// KYBER WORKER TASK FOR GCC (One-shot: processes CT and exits)
// ============================================================================
// This task receives Kyber CT from callback and does decapsulation
// safely in task context (NOT ISR). Deletes itself after completion.
void kyber_decaps_task(void *pvParameters) {
    kyber_ct_item_t ct_item;
    uint8_t local_ss[KYBER_SHAREDSECRET_BYTES];
    
    // Wait for CT from callback (with reasonable timeout)
    if (xQueueReceive(kyber_ct_queue, &ct_item, pdMS_TO_TICKS(30000)) == pdTRUE) {
        ESP_LOGI(TAG, "   📦 Worker task processing Kyber ciphertext...");
        
        // Decapsulate (HEAVY CRYPTO - safe in task context)
        if (kyber_decaps(kyber_sk, ct_item.ciphertext, local_ss) == ESP_OK) {
            ESP_LOGI(TAG, "Decapsulation successful!");
            
            // Derive session keys
            kyber_derive_session_keys(local_ss, &session);
            ESP_LOGI(TAG, "Session keys derived, secure channel ready!");
            ESP_LOGI(TAG, "=====================================================");
            ESP_LOGI(TAG, " ✅ Secure channel established with UAV!");
            ESP_LOGI(TAG, "=====================================================");
            
            // Clear secrets
            kyber_secure_memzero(kyber_sk, sizeof(kyber_sk));
            kyber_secure_memzero(local_ss, sizeof(local_ss));
        } else {
            ESP_LOGE(TAG, "Decapsulation failed!");
        }
    } else {
        ESP_LOGW(TAG, "   ⏱️ Kyber decaps task timed out waiting for CT");
    }
    
    // One-shot task: delete self after completion
    ESP_LOGI(TAG, "   🗑️ Kyber decaps task completed, deleting self");
    vTaskDelete(NULL);
}

// ========================================
// ★ MAIN DISTANCE MONITORING TASK
// All heavy operations happen here, NOT in callback
// ========================================
void distance_monitor_task(void *param) {
    static int no_signal_count = 0;
    static uint32_t challenge_sent_time = 0;
    static bool challenge_pending = false;
    
    #define AUTH_RESPONSE_TIMEOUT_MS 5000  // 7 seconds timeout
    
    while (1) {
        // ========================================
        // STATE: IDLE - Waiting for UAV
        // ========================================
        if (current_state == STATE_IDLE && is_uav_in_range()) {
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "┌─────────────────────────────────────┐");
            ESP_LOGI(TAG, "│   🚁 UAV DETECTED IN PROXIMITY      │");
            ESP_LOGI(TAG, "│  Starting Authentication Protocol   │");
            ESP_LOGI(TAG, "└─────────────────────────────────────┘");
            
            current_state = STATE_AUTHENTICATING;
            
            // Generate random challenge
            auth_message_t auth_msg = {0};
            generate_random_challenge(auth_msg.challenge);
            auth_msg.timestamp = esp_timer_get_time() / 1000;
            
            // Prepare ESP-NOW message
            espnow_message_t msg = {
                .type = MSG_CHALLENGE,
                .data_len = sizeof(auth_message_t)
            };
            memcpy(msg.data, &auth_msg, sizeof(auth_message_t));
            
            // Send challenge to UAV
            if (espnow_send_message(uav_mac[0], &msg) == ESP_OK) {
                ESP_LOGI(TAG, "  → Challenge transmitted to UAV");
                ESP_LOGI(TAG, "  ⏱️  Waiting for response... (%d second timeout)", AUTH_RESPONSE_TIMEOUT_MS/1000);
                ESP_LOGI(TAG, "");
                
                challenge_sent_time = esp_timer_get_time() / 1000;
                challenge_pending = true;
            } else {
                ESP_LOGE(TAG, "  ✗ Failed to send challenge");
                current_state = STATE_IDLE;
                challenge_pending = false;
            }
        }
        
        // ========================================
        // STATE: AUTHENTICATING - Check for response
        // ========================================
        if (challenge_pending && current_state == STATE_AUTHENTICATING) {
            espnow_message_t response_msg;
            
            // ★ Wait for response from queue (non-blocking with timeout)
            if (xQueueReceive(auth_response_queue, &response_msg, pdMS_TO_TICKS(100)) == pdTRUE) {
                ESP_LOGI(TAG, "");
                ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                ESP_LOGI(TAG, "  AUTHENTICATION RESPONSE RECEIVED");
                ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                
                auth_message_t auth_msg;
                memcpy(&auth_msg, response_msg.data, sizeof(auth_message_t));
                
                // Verify the response
                if (verify_response(&auth_msg)) {
                    // ✅ AUTHORIZED
                    ESP_LOGI(TAG, "");
                    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
                    ESP_LOGI(TAG, "║     ✓ AUTHORIZATION SUCCESSFUL        ║");
                    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
                    ESP_LOGI(TAG, "");
                    ESP_LOGI(TAG, "Device Information:");
                    ESP_LOGI(TAG, "  Device ID (MAC): ");
                    print_hex("  ", auth_msg.device_id, DEVICE_ID_SIZE);
                    ESP_LOGI(TAG, "  Timestamp: %lu ms", auth_msg.timestamp);
                    ESP_LOGI(TAG, "  Status: TRUSTED DEVICE ✓");
                    ESP_LOGI(TAG, "");
                    ESP_LOGI(TAG, "Next Phase: Establishing Secure Channel...");
                    ESP_LOGI(TAG, "");
                    
                    uav_authenticated = true;
                    current_state = STATE_AUTHENTICATED;
                    challenge_pending = false;
                    ESP_LOGI(TAG, "✓ Ready for secure communication");
                    //////////////// Objective - 2//////////
                    ESP_LOGI(TAG, "Starting post-quantum key agreement...");

                    // Step 1: Generate Kyber keypair
                    if (kyber_keygen(kyber_pk, kyber_sk) == ESP_OK) {
                        ESP_LOGI(TAG, "Kyber keypair generated");
                        // Step 2: Send GCC public key to UAV
                        espnow_message_t pk_msg = {
                            .type = MSG_KYBER_PK_OFFER,
                            .data_len = KYBER_PUBLICKEY_BYTES
                        };
                        memcpy(pk_msg.data, kyber_pk, KYBER_PUBLICKEY_BYTES);
                        espnow_send_message(uav_mac[0], &pk_msg);
                        ESP_LOGI(TAG, "Sent Kyber public key to UAV");
                    } else {
                        ESP_LOGE(TAG, "Kyber key generation failed!");
                    }

                    //////////////////////////////////////
                } else {
                    // ❌ NOT AUTHORIZED
                    ESP_LOGI(TAG, "");
                    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
                    ESP_LOGI(TAG, "║     ✗ AUTHORIZATION FAILED           ║");
                    ESP_LOGI(TAG, "║     UNAUTHORIZED DEVICE DETECTED      ║");
                    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
                    ESP_LOGI(TAG, "");
                    ESP_LOGI(TAG, "Security Alert:");
                    ESP_LOGI(TAG, "  Response received but FAILED verification");
                    ESP_LOGI(TAG, "  Possible causes:");
                    ESP_LOGI(TAG, "    1. Invalid PUF response");
                    ESP_LOGI(TAG, "    2. Challenge-response mismatch");
                    ESP_LOGI(TAG, "    3. Replay attack detected");
                    ESP_LOGI(TAG, "  Status: ACCESS DENIED ✗");
                    ESP_LOGI(TAG, "");
                    
                    current_state = STATE_IDLE;
                    challenge_pending = false;
                    uav_authenticated = false;
                }
                
                ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            }
            
            // ★ Check for timeout
            uint32_t current_time = esp_timer_get_time() / 1000;
            uint32_t elapsed_time = current_time - challenge_sent_time;
            
            if (elapsed_time > AUTH_RESPONSE_TIMEOUT_MS && is_uav_in_range()) {
                ESP_LOGE(TAG, "");
                ESP_LOGE(TAG, "╔═══════════════════════════════════════╗");
                ESP_LOGE(TAG, "║  ✗ AUTHORIZATION TIMEOUT              ║");
                ESP_LOGE(TAG, "║  UNAUTHORIZED UAV DETECTED             ║");
                ESP_LOGE(TAG, "╚═══════════════════════════════════════╝");
                ESP_LOGE(TAG, "");
                ESP_LOGE(TAG, "⚠️  SECURITY ALERT ⚠️");
                ESP_LOGE(TAG, "  No valid response received");
                ESP_LOGE(TAG, "  Timeout period: %d ms", AUTH_RESPONSE_TIMEOUT_MS);
                ESP_LOGE(TAG, "  Elapsed time: %lu ms", elapsed_time);
                ESP_LOGE(TAG, "  Status: ACCESS DENIED ✗");
                ESP_LOGE(TAG, "  Action: Unknown/Spoofed UAV rejected");
                ESP_LOGE(TAG, "");
                
                current_state = STATE_IDLE;
                challenge_pending = false;
                uav_authenticated = false;
            }
        }
        
        // ========================================
        // Check if UAV left range
        // ========================================
        if (current_state != STATE_IDLE && !is_uav_in_range()) {
            no_signal_count++;
            if (no_signal_count > 3) {  // 3 * 500ms = 1.5 seconds
                ESP_LOGI(TAG, "");
                ESP_LOGI(TAG, "┌─────────────────────────────────────┐");
                ESP_LOGI(TAG, "│   🚁 UAV DEPARTED FROM RANGE        │");
                ESP_LOGI(TAG, "│  Session terminated                 │");
                ESP_LOGI(TAG, "└─────────────────────────────────────┘");
                ESP_LOGI(TAG, "");
                
                uav_authenticated = false;
                current_state = STATE_IDLE;
                challenge_pending = false;
                no_signal_count = 0;
                
                ESP_LOGI(TAG, "Monitoring for UAV...");
                ESP_LOGI(TAG, "");
            }
        } else {
            no_signal_count = 0;  // Reset counter
        }
        
        // ★ SAFE: vTaskDelay can be called here in a registered task!
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void app_main(void) {
    printf("\n================================\n");
    printf("  GCC - Ground Control Center\n");
    printf("================================\n");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    
    // Initialize modules
    auth_init();
    distance_sensor_init();
    espnow_init(true);  // GCC mode

    kyber_init();


    // ════════════════════════════════════════
    // ENROLL UAVs INTO DATABASE
    // ════════════════════════════════════════

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   Enrolling UAVs into Database         ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    // Enroll UAV-1
    uint8_t uav1_mac[10][6] = {{0xB0, 0xCB, 0xD8, 0xC9, 0x0B, 0x18}};
    uint8_t uav1_helper[32] = {0};

    if (enroll_new_uav(uav1_mac[0], uav1_helper) == 0) {
        ESP_LOGI(TAG, "✓ UAV-1 enrolled successfully");
    } else {
        ESP_LOGE(TAG, "✗ Failed to enroll UAV-1");
    }

    // ════════════════════════════════════════

    
    // ★ CREATE response queue
    auth_response_queue = xQueueCreate(5, sizeof(espnow_message_t));
    if (auth_response_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create authentication response queue!");
        return;
    }
    
    // Set callback (SIMPLE - just queues messages)
    espnow_set_recv_callback(gcc_recv_callback);
    
    // ========================================
    // Create Kyber Decaps Queue and Task
    // ========================================
    kyber_ct_queue = xQueueCreate(2, sizeof(kyber_ct_item_t));
    if (kyber_ct_queue == NULL) {
        ESP_LOGE(TAG, "✗ Failed to create Kyber CT queue!");
        return;
    }
    if (xTaskCreate(kyber_decaps_task, "kyber_decaps", 16384, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "✗ Failed to create Kyber decaps task!");
        return;
    }
    ESP_LOGI(TAG, "✓ Kyber decaps task created (handles crypto in task context)");
    
    ESP_LOGI(TAG, "All systems ready");
    ESP_LOGI(TAG, "Monitoring for UAV...");
    
    // ★ CREATE distance monitoring task
    xTaskCreate(distance_monitor_task, "distance_mon", 16384, NULL, 5, NULL);
}
