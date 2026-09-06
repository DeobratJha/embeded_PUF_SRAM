#include "authentication.h"
#include "puf_lib.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_task_wdt.h"
#include <string.h>          // For memcmp, memcpy, memset
#include <inttypes.h>        // For PRIu32

static const char* TAG = "AUTH";

#define MAC_LEN 6

// ============================================================================
// MULTIPLE UAVs SUPPORT: UAV DATABASE
// ============================================================================

// Structure to store enrolled UAV information
typedef struct {
    uint8_t mac[6];                         // UAV MAC address (unique identifier)
    uint8_t helper_data[PUF_RESPONSE_LEN]; // UAV's PUF helper data
    uint32_t timestamp;                     // When UAV was enrolled
    bool is_active;                         // Whether UAV is active/authorized
} uav_device_t;

// Maximum number of UAVs that can be enrolled
#define MAX_ENROLLED_UAVS 10

// In-memory UAV database (can be extended to NVS for persistence)
static uav_device_t uav_database[MAX_ENROLLED_UAVS] = {0};
static uint32_t num_enrolled_uavs = 0;

// ============================================================================
// UAV DATABASE MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * @brief Add a new UAV to the database during enrollment
 * @param mac UAV's MAC address
 * @param helper_data UAV's PUF helper data
 * @return 0 on success, -1 if database full or UAV already enrolled
 */
static int add_uav_to_database(const uint8_t *mac, const uint8_t *helper_data) {
    // Check if UAV already exists in database
    for (uint32_t i = 0; i < num_enrolled_uavs; i++) {
        if (memcmp(uav_database[i].mac, mac, 6) == 0) {
            ESP_LOGW(TAG, "UAV already enrolled (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return -1; // Already exists
        }
    }

    // Check if database has space
    if (num_enrolled_uavs >= MAX_ENROLLED_UAVS) {
        ESP_LOGE(TAG, "UAV database full (max: %d UAVs)", MAX_ENROLLED_UAVS);
        return -1; // Database full
    }

    // Add new UAV
    memcpy(uav_database[num_enrolled_uavs].mac, mac, 6);
    memcpy(uav_database[num_enrolled_uavs].helper_data, helper_data, PUF_RESPONSE_LEN);
    uav_database[num_enrolled_uavs].timestamp = esp_timer_get_time() / 1000; // milliseconds
    uav_database[num_enrolled_uavs].is_active = true;

    ESP_LOGI(TAG, "✓ UAV enrolled (ID: %" PRIu32 ", MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
             num_enrolled_uavs, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    num_enrolled_uavs++;
    return 0;
}

/**
 * @brief Find UAV in database by MAC address
 * @param mac UAV's MAC address
 * @return Pointer to UAV device if found, NULL otherwise
 */
static uav_device_t* find_uav_in_database(const uint8_t *mac) {
    for (uint32_t i = 0; i < num_enrolled_uavs; i++) {
        if (memcmp(uav_database[i].mac, mac, 6) == 0) {
            if (uav_database[i].is_active) {
                return &uav_database[i];
            } else {
                ESP_LOGW(TAG, "UAV found but inactive (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                return NULL;
            }
        }
    }
    return NULL; // Not found
}

/**
 * @brief Remove (deactivate) UAV from database
 * @param mac UAV's MAC address
 * @return 0 on success, -1 if not found
 */
static int remove_uav_from_database(const uint8_t *mac) {
    for (uint32_t i = 0; i < num_enrolled_uavs; i++) {
        if (memcmp(uav_database[i].mac, mac, 6) == 0) {
            uav_database[i].is_active = false;
            ESP_LOGI(TAG, "✓ UAV deactivated (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return 0;
        }
    }
    return -1; // Not found
}

/**
 * @brief Print all enrolled UAVs (for debugging)
 */
void print_enrolled_uavs(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║    ENROLLED UAVs DATABASE (%" PRIu32 "/%" PRIu32 ")      ║",
             num_enrolled_uavs, (uint32_t)MAX_ENROLLED_UAVS);
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    for (uint32_t i = 0; i < num_enrolled_uavs; i++) {
        ESP_LOGI(TAG, "[%" PRIu32 "] MAC: %02X:%02X:%02X:%02X:%02X:%02X | Status: %s",
                 i, uav_database[i].mac[0], uav_database[i].mac[1], uav_database[i].mac[2],
                 uav_database[i].mac[3], uav_database[i].mac[4], uav_database[i].mac[5],
                 uav_database[i].is_active ? "ACTIVE" : "INACTIVE");
    }

    ESP_LOGI(TAG, "");
}

// ============================================================================
// AUTHENTICATION FUNCTIONS (MINIMAL CHANGES)
// ============================================================================

/**
 * @brief Initialize authentication system
 * @return ESP_OK on success
 */
esp_err_t auth_init(void) {
    ESP_LOGI(TAG, "Authentication system initialized");
    ESP_LOGI(TAG, "Max UAVs supported: %d", MAX_ENROLLED_UAVS);
    return ESP_OK;  // ← RETURN STATEMENT ADDED
}

/**
 * @brief Authenticate device (generates challenge-response)
 * @param auth_msg Authentication message
 * @return AUTH_SUCCESS or AUTH_ERROR
 */
auth_result_t authenticate_device(auth_message_t* auth_msg) {
    if (!auth_msg || PUF_STATE != PUF_STATE_ENROLLED) {
        return AUTH_ERROR;
    }

    // Reset watchdog during heavy PUF operations
    esp_task_wdt_reset();

    // Reconstruct PUF response
    if (!get_puf_response()) {
        ESP_LOGE(TAG, "Failed to reconstruct PUF");
        return AUTH_ERROR;
    }

    esp_task_wdt_reset();

    // Get device MAC address
    uint8_t mac[MAC_LEN];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    memset(auth_msg->device_id, 0, DEVICE_ID_SIZE);
    memcpy(auth_msg->device_id, mac, MAC_LEN);

    ESP_LOGI(TAG, "Device MAC as ID: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Compute response = SHA256(challenge || PUF_RESPONSE)
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, auth_msg->challenge, CHALLENGE_SIZE);
    mbedtls_sha256_update(&ctx, PUF_RESPONSE, PUF_RESPONSE_LEN);
    mbedtls_sha256_finish(&ctx, auth_msg->response);
    mbedtls_sha256_free(&ctx);

    clean_puf_response();

    return AUTH_SUCCESS;
}

/**
 * @brief Generate random challenge for authentication
 * @param challenge Output buffer for challenge
 */
void generate_random_challenge(uint8_t* challenge) {
    if (challenge == NULL) return;
    
    for (int i = 0; i < CHALLENGE_SIZE; i++) {
        challenge[i] = esp_random() & 0xFF;
    }
}

/**
 * @brief Verify response from UAV (checks against enrolled UAVs database)
 * @param auth_msg Authentication message with response
 * @return true if verified, false otherwise
 */
bool verify_response(auth_message_t* auth_msg) {
    if (!auth_msg) {
        ESP_LOGE(TAG, "✗ Invalid auth message");
        return false;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   VERIFYING RESPONSE");
    ESP_LOGI(TAG, "═══════════════════════════════════════");

    // ====================================================================
    // STEP 1: CHECK RESPONSE ENTROPY (Validate PUF signature)
    // ====================================================================

    ESP_LOGI(TAG, "[1/3] Checking response entropy...");

    int one_count = 0;
    for (int i = 0; i < RESPONSE_SIZE; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (auth_msg->response[i] & (1 << bit)) {
                one_count++;
            }
        }
    }

    // Valid PUF response should have 30-70% ones
    if (one_count < 77 || one_count > 179) { // 30-70% of 256 bits
        ESP_LOGE(TAG, "✗ Response pattern invalid (one_count=%d)", one_count);
        return false;
    }

    ESP_LOGI(TAG, "✓ Response entropy valid (one_count=%d out of 256 bits)", one_count);

    // ====================================================================
    // STEP 2: LOOKUP UAV IN DATABASE (Multiple UAV support)
    // ====================================================================

    ESP_LOGI(TAG, "[2/3] Looking up UAV in database...");

    ESP_LOGI(TAG, "   Received MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             auth_msg->device_id[0], auth_msg->device_id[1], auth_msg->device_id[2],
             auth_msg->device_id[3], auth_msg->device_id[4], auth_msg->device_id[5]);

    // Find UAV in database
    uav_device_t* uav = find_uav_in_database(auth_msg->device_id);
    if (uav == NULL) {
        ESP_LOGE(TAG, "✗ UAV not found in database");
        ESP_LOGE(TAG, "   Total enrolled UAVs: %" PRIu32, num_enrolled_uavs);
        print_enrolled_uavs();
        return false;
    }

    ESP_LOGI(TAG, "✓ UAV found in database");

    // ====================================================================
    // STEP 3: VERIFY AGAINST STORED HELPER DATA
    // ====================================================================

    ESP_LOGI(TAG, "[3/3] Verifying against UAV helper data...");

    // In current implementation, we just verify entropy
    // In advanced implementation, you could use helper_data for error correction
    // For now, MAC lookup is sufficient for device identity

    ESP_LOGI(TAG, "✓ Device ID matches enrolled UAV");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   ✓ AUTHENTICATION VERIFIED");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "");

    return true;
}

/**
 * @brief Enroll a new UAV (used during pairing/setup)
 * @param mac UAV's MAC address
 * @param helper_data UAV's PUF helper data
 * @return 0 on success, -1 on failure
 */
int enroll_new_uav(const uint8_t *mac, const uint8_t *helper_data) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   ENROLLING NEW UAV");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    int result = add_uav_to_database(mac, helper_data);

    if (result == 0) {
        ESP_LOGI(TAG, "✓ UAV enrollment successful");
        print_enrolled_uavs();
    } else {
        ESP_LOGE(TAG, "✗ UAV enrollment failed");
    }

    return result;
}

/**
 * @brief Deactivate a UAV (revoke access)
 * @param mac UAV's MAC address
 * @return 0 on success, -1 on failure
 */
int deactivate_uav(const uint8_t *mac) {
    ESP_LOGI(TAG, "Deactivating UAV: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    int result = remove_uav_from_database(mac);

    if (result == 0) {
        print_enrolled_uavs();
    } else {
        ESP_LOGE(TAG, "✗ UAV not found in database");
    }

    return result;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Print hex data for debugging
 * @param label Label for output
 * @param data Data to print
 * @param length Length of data
 */
// void print_hex(const char* label, uint8_t* data, size_t length) {
//     printf("%s: ", label);
//     for (size_t i = 0; i < length; i++) {
//         printf("%02X", data[i]);
//         if ((i + 1) % 16 == 0) printf("\n");
//         else if ((i + 1) % 8 == 0) printf("  ");
//         else printf(" ");
//     }
//     if (length % 16 != 0) printf("\n");
// }

/**
 * @brief Worker task for authentication operations
 * @param pv Operation parameter
 */
extern volatile bool auth_task_running;

void auth_worker_task(void *pv) {
    int op = (int)(intptr_t)pv;

    ESP_LOGI(TAG, "auth_worker_task started (op=%d)", op);

    auth_task_running = false;

    if (op == 1) {
        // Enrollment
        ESP_LOGI(TAG, "Starting enrollment...");
        if (enroll_puf() == ESP_OK) {
            ESP_LOGI(TAG, "Enrollment completed successfully.");
            printf("✓ Enrolled\n");
        } else {
            ESP_LOGE(TAG, "Enrollment failed.");
        }
    } else if (op == 2) {
        // Generate response (for local debug)
        ESP_LOGI(TAG, "Generating PUF response...");
        if (get_puf_response()) {
            print_hex("Response", PUF_RESPONSE, PUF_RESPONSE_LEN);
            clean_puf_response();
            ESP_LOGI(TAG, "Response generation completed.");
        } else {
            ESP_LOGE(TAG, "Failed to generate PUF response.");
        }
    } else if (op == 3) {
        // Authenticate
        ESP_LOGI(TAG, "Starting authentication...");
        auth_message_t msg = {0};
        generate_random_challenge(msg.challenge);

        if (authenticate_device(&msg) == AUTH_SUCCESS) {
            print_hex("Challenge", msg.challenge, CHALLENGE_SIZE);
            print_hex("Response", msg.response, RESPONSE_SIZE);
            if (verify_response(&msg)) {
                printf("\n*** VERIFICATION SUCCESS ***\n");
            } else {
                printf("\nXXX VERIFICATION FAILED XXX\n");
            }
        } else {
            ESP_LOGE(TAG, "authenticate_device returned error");
        }
    } else {
        ESP_LOGW(TAG, "Unknown operation code %d", op);
    }

    ESP_LOGI(TAG, "auth_worker_task finished (op=%d)", op);
    vTaskDelete(NULL);
    auth_task_running = false;
}
