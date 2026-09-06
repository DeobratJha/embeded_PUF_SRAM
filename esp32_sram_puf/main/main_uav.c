#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"  // Add semaphore support
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_sleep.h"
#include "puf_lib.h"
#include "authentication.h"
#include "esp_now_comm.h"
#include "kyber_key_agreement.h"

#define MSG_KYBER_PK_OFFER     10
#define MSG_KYBER_CT_RESPONSE  11

static const char* TAG = "UAV";

// Queue for safe message handling
static QueueHandle_t auth_queue = NULL;


/////////////////objective 2
// ---------------------- Kyber Global Variables (UAV) ----------------------
static uint8_t kyber_pk[KYBER_PUBLICKEY_BYTES];
static uint8_t kyber_sk[KYBER_SECRETKEY_BYTES];
static uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
static uint8_t kyber_ss[KYBER_SHAREDSECRET_BYTES];
static kyber_session_t session;

// ISR-safe queue: Only pass lightweight data from callback
typedef struct {
    uint8_t peer_mac[6];
    uint8_t public_key[KYBER_PUBLICKEY_BYTES];  // Just the PK, not ciphertext
} kyber_work_item_t;

static QueueHandle_t kyber_work_queue = NULL;
// Note: gcc_mac is already declared in esp_now_comm.h as extern
// --------------------------------------------------------------------------

///////////////////


// ============================================================================
// ESP-NOW RECEIVE CALLBACK
// ============================================================================

void uav_recv_callback(const uint8_t *mac, const uint8_t *data, int len) {
    espnow_message_t *msg = (espnow_message_t *)data;
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "📡 ESP-NOW MESSAGE RECEIVED");
    ESP_LOGI(TAG, "   From MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ESP_LOGI(TAG, "   Data length: %d bytes", len);
    ESP_LOGI(TAG, "   Message type: %d", msg->type);

    // ===============================================================
    // 🚀 OBJECTIVE 2: Handle Kyber Public Key Offer
    // ===============================================================
    if (msg->type == MSG_KYBER_PK_OFFER) {
        ESP_LOGI(TAG, "🔑 Received Kyber Public Key Offer from GCC");

        // ISR-SAFE: Only queue the PK, let task do the heavy crypto work
        if (kyber_work_queue != NULL) {
            kyber_work_item_t work_item;
            memcpy(work_item.peer_mac, mac, 6);
            memcpy(work_item.public_key, msg->data, KYBER_PUBLICKEY_BYTES);
            
            BaseType_t higher_priority_task_woken = pdFALSE;
            xQueueSendFromISR(kyber_work_queue, &work_item, &higher_priority_task_woken);
            if (higher_priority_task_woken) {
                portYIELD_FROM_ISR();
            }
        }

        return; // <— Prevent queueing this message further
    }
    // ===============================================================
    // END OF OBJECTIVE 2 BLOCK
    // ===============================================================


    // Queue the message safely (Objective 1: PUF Authentication)
    ESP_LOGI(TAG, "   → Queuing for authentication task...");
    if (auth_queue != NULL) {
        if (xQueueSend(auth_queue, msg, 0) == pdTRUE) {
            ESP_LOGI(TAG, "   ✓ Message queued successfully");
        } else {
            ESP_LOGE(TAG, "   ✗ Queue is full - message dropped!");
        }
    } else {
        ESP_LOGE(TAG, "   ✗ Queue not initialized!");
    }
}


// ============================================================================
// AUTHENTICATION TASK
// ============================================================================

void authentication_task(void *param) {
    espnow_message_t msg;
    int auth_attempt = 0;
    
    while (1) {
        // Wait for message in queue
        if (xQueueReceive(auth_queue, &msg, portMAX_DELAY)) {
            auth_attempt++;
            
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "═══════════════════════════════════════");
            ESP_LOGI(TAG, "  AUTHENTICATION ATTEMPT #%d", auth_attempt);
            ESP_LOGI(TAG, "═══════════════════════════════════════");
            
            // Validate message size
            ESP_LOGI(TAG, "[1/6] Checking message size...");
            ESP_LOGI(TAG, "   Received size: %d bytes", msg.data_len);
            ESP_LOGI(TAG, "   Expected size: %d bytes", sizeof(auth_message_t));
            
            if (msg.data_len != sizeof(auth_message_t)) {
                ESP_LOGE(TAG, "   ✗ FAILED - Size mismatch!");
                continue;
            }
            ESP_LOGI(TAG, "   ✓ Size OK");
            
            // Validate message type
            ESP_LOGI(TAG, "[2/6] Checking message type...");
            ESP_LOGI(TAG, "   Message type: %d", msg.type);
            
            if (msg.type != MSG_CHALLENGE) {
                ESP_LOGW(TAG, "   ✗ Unknown message type");
                continue;
            }
            ESP_LOGI(TAG, "   ✓ Type OK");
            
            // Extract challenge
            ESP_LOGI(TAG, "[3/6] Extracting challenge from message...");
            auth_message_t auth_msg;
            memcpy(&auth_msg, msg.data, sizeof(auth_message_t));
            
            ESP_LOGI(TAG, "   Challenge (first 8 bytes):");
            print_hex("   ", auth_msg.challenge, 8);
            ESP_LOGI(TAG, "   ✓ Challenge extracted");
            
            // Authenticate device
            ESP_LOGI(TAG, "[4/6] Calling authenticate_device()...");
            
            if (authenticate_device(&auth_msg) == AUTH_SUCCESS) {
                ESP_LOGI(TAG, "   ✓ PUF response generated successfully");
                
                // Verify response
                ESP_LOGI(TAG, "[5/6] Verifying generated response...");
                ESP_LOGI(TAG, "   Response (first 8 bytes):");
                print_hex("   ", auth_msg.response, 8);
                
                // Check entropy
                int one_count = 0;
                for (int i = 0; i < RESPONSE_SIZE; i++) {
                    for (int bit = 0; bit < 8; bit++) {
                        if (auth_msg.response[i] & (1 << bit)) {
                            one_count++;
                        }
                    }
                }
                ESP_LOGI(TAG, "   Response entropy: %d ones out of 256 bits", one_count);
                
                ESP_LOGI(TAG, "   Device ID (MAC):");
                print_hex("   ", auth_msg.device_id, 6);
                ESP_LOGI(TAG, "   ✓ Response OK");
                
                // Send response
                ESP_LOGI(TAG, "[6/6] Sending response back to GCC...");
                
                espnow_message_t response_msg = {
                    .type = MSG_RESPONSE,
                    .data_len = sizeof(auth_message_t)
                };
                memcpy(response_msg.data, &auth_msg, sizeof(auth_message_t));
                
                esp_err_t send_result = espnow_send_message(gcc_mac, &response_msg);
                if (send_result == ESP_OK) {
                    ESP_LOGI(TAG, "   → Response sent successfully!");
                    ESP_LOGI(TAG, "   ✓ AUTHENTICATION COMPLETE");
                } else {
                    ESP_LOGE(TAG, "   ✗ Failed to send response (error: %d)", send_result);
                }
                
                // Delay before next iteration
                vTaskDelay(pdMS_TO_TICKS(200));
                
            } else {
                ESP_LOGE(TAG, "[4/6] ✗ authenticate_device() FAILED");
            }
            
            ESP_LOGI(TAG, "═══════════════════════════════════════");
            ESP_LOGI(TAG, "");
            
            // Small delay even on error path
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

// ============================================================================
// HELPER FUNCTION: PRINT ENROLLMENT DATA
// ============================================================================

void print_helper_data(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG, "║        UAV ENROLLMENT DATA            ║");
    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
    
    puf_enrollment_data_t enroll_data;
    
    if (load_enrollment_data(&enroll_data) == ESP_OK) {
        ESP_LOGI(TAG, "Helper Data (copy this to GCC):");
        print_hex("  ", enroll_data.helper_data, PUF_RESPONSE_LEN);
        
        ESP_LOGI(TAG, "Stable Bit Count: %d", enroll_data.stable_bit_count);
        
        ESP_LOGI(TAG, "Stable Bit Indices (first 10):");
        for (int i = 0; i < 10 && i < enroll_data.stable_bit_count; i++) {
            printf("  [%d]: %d\n", i, enroll_data.stable_bit_indices[i]);
        }
    } else {
        ESP_LOGE(TAG, "Failed to load enrollment data");
    }
    
    ESP_LOGI(TAG, "");
}

// ============================================================================
// KYBER WORKER TASK (One-shot: processes message and exits)
// ============================================================================
// This task receives Kyber PK from callback and does ALL crypto operations
// safely in task context (NOT ISR). Deletes itself after completion.
void kyber_worker_task(void *pvParameters) {
    kyber_work_item_t work_item;
    uint8_t local_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t local_ss[KYBER_SHAREDSECRET_BYTES];
    espnow_message_t ct_msg;
    
    // Wait for work from callback (with reasonable timeout)
    if (xQueueReceive(kyber_work_queue, &work_item, pdMS_TO_TICKS(30000)) == pdTRUE) {
        ESP_LOGI(TAG, "   📦 Worker task processing Kyber PK...");
        
        // Step 1: Encapsulate (HEAVY CRYPTO - safe in task context)
        if (kyber_encaps(work_item.public_key, local_ct, local_ss) == ESP_OK) {
            ESP_LOGI(TAG, "   ✓ Kyber encapsulation successful");

            // Step 2: Derive session keys (HEAVY CRYPTO)
            kyber_derive_session_keys(local_ss, &session);
            ESP_LOGI(TAG, "   ✓ Session keys derived");

            // Step 3: Send ciphertext back to GCC
            ct_msg.type = MSG_KYBER_CT_RESPONSE;
            ct_msg.data_len = KYBER_CIPHERTEXT_BYTES;
            memcpy(ct_msg.data, local_ct, KYBER_CIPHERTEXT_BYTES);

            esp_err_t send_result = espnow_send_message(work_item.peer_mac, &ct_msg);
            if (send_result == ESP_OK) {
                ESP_LOGI(TAG, "   → Ciphertext sent to GCC successfully");
                ESP_LOGI(TAG, "=====================================================");
                ESP_LOGI(TAG, " ✅ Secure channel established with GCC!");
                ESP_LOGI(TAG, "=====================================================");
            } else {
                ESP_LOGE(TAG, "   ✗ Failed to send ciphertext (error %d)", send_result);
            }

            // Clear secrets
            kyber_secure_memzero(local_ss, sizeof(local_ss));
        } else {
            ESP_LOGE(TAG, "   ✗ Kyber encapsulation failed");
        }
    } else {
        ESP_LOGW(TAG, "   ⏱️ Kyber worker task timed out waiting for work");
    }
    
    // One-shot task: delete self after completion
    ESP_LOGI(TAG, "   🗑️ Kyber worker task completed, deleting self");
    vTaskDelete(NULL);
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

void app_main() {
    printf("\n================================\n");
    printf("  UAV - Unmanned Aerial Vehicle\n");
    printf("  Hardware PUF Enabled\n");
    printf("================================\n\n");
    
    // ========================================
    // 1. Initialize NVS Flash
    // ========================================
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    ESP_LOGI(TAG, "✓ NVS initialized");
    
    // ========================================
    // 2. Check Deep Sleep Wake-up
    // ========================================
    esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
    if (wakeup_reason == ESP_SLEEP_WAKEUP_TIMER) {
        ESP_LOGI(TAG, "✓ Woke from deep sleep - PUF data ready");
    }
    
    // ========================================
    // 3. Initialize PUF Library (NO ENROLLMENT)
    // ========================================
    if (puflib_init() != ESP_OK) {
        ESP_LOGE(TAG, "✗ PUF init failed!");
        return;
    }
    ESP_LOGI(TAG, "✓ PUF library initialized");
    
    // ========================================
    // 4. ZERO-STORED-KEY ARCHITECTURE
    // ========================================
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   ZERO-STORED-KEY BOOT SEQUENCE       ║");
    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    
    uint8_t device_seed[32];
    
    // Step 1: Derive seed from PUF (EVERY BOOT)
    ESP_LOGI(TAG, "[1/3] Deriving device seed from PUF...");
    if (derive_device_seed_simple(device_seed) != ESP_OK) {
        ESP_LOGE(TAG, "✗ Failed to derive device seed - cannot proceed!");
        return;
    }
    
    // Step 2: Generate deterministic Kyber keypair
    ESP_LOGI(TAG, "[2/3] Generating deterministic Kyber keypair...");
    if (kyber_keygen_deterministic(device_seed, kyber_pk, kyber_sk) != ESP_OK) {
        ESP_LOGE(TAG, "✗ Failed to generate Kyber keys!");
        secure_zeroize(device_seed, sizeof(device_seed));
        return;
    }
    
    // Step 3: Zeroize seed (no longer needed)
    ESP_LOGI(TAG, "[3/3] Zeroizing seed...");
    secure_zeroize(device_seed, sizeof(device_seed));
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   ✓ ZERO-STORED-KEY BOOT COMPLETE    ║");
    ESP_LOGI(TAG, "║   Hardware-rooted identity ready      ║");
    ESP_LOGI(TAG, "║   No secrets stored in flash          ║");
    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    
    // ========================================
    // 5. Run Hardware PUF Tests (Optional)
    // ========================================
    #ifdef ENABLE_PUF_TESTS
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== RUNNING HARDWARE PUF TESTS ===");
    
    test_hardware_puf();
    // test_puf_enrollment_reconstruction();  // DISABLED - no enrollment
    test_freeze_detection();
    
    ESP_LOGI(TAG, "=== TESTS COMPLETE ===");
    ESP_LOGI(TAG, "");
    #endif
    
    // ========================================
    // 6. Initialize Authentication
    // ========================================

    auth_init();
    kyber_init();

    ESP_LOGI(TAG, "✓ Authentication initialized");
    
    // ========================================
    // 7. Create Queue for Message Handling
    // ========================================
    auth_queue = xQueueCreate(5, sizeof(espnow_message_t));
    if (auth_queue == NULL) {
        ESP_LOGE(TAG, "✗ Failed to create authentication queue!");
        return;
    }
    ESP_LOGI(TAG, "✓ Authentication queue created (5 items, %d bytes each)",
             sizeof(espnow_message_t));
    
    // ========================================
    // 8. Create Authentication Task
    // ========================================
    if (xTaskCreate(authentication_task, "auth_task", 16384, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "✗ Failed to create authentication task!");
        return;
    }
    ESP_LOGI(TAG, "✓ Authentication task created (16KB stack)");
    
    // ========================================
    // 9. Create Kyber Worker Queue and Task
    // ========================================
    kyber_work_queue = xQueueCreate(2, sizeof(kyber_work_item_t));
    if (kyber_work_queue == NULL) {
        ESP_LOGE(TAG, "✗ Failed to create Kyber work queue!");
        return;
    }
    if (xTaskCreate(kyber_worker_task, "kyber_worker", 16384, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "✗ Failed to create Kyber worker task!");
        return;
    }
    ESP_LOGI(TAG, "✓ Kyber worker task created (handles crypto in task context)");
    
    // ========================================
    // 10. Initialize ESP-NOW
    // ========================================
    espnow_init(false);  // false = UAV mode
    espnow_set_recv_callback(uav_recv_callback);
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔═══════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   ✓ UAV READY - WAITING FOR GCC      ║");
    ESP_LOGI(TAG, "╚═══════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
}
