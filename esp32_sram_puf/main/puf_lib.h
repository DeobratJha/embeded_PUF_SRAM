#ifndef PUF_LIB_H
#define PUF_LIB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_system.h"
#include "esp_sleep.h"
#include "nvs.h"

// ============================================================================
// HARDWARE PUF MEMORY REGIONS
// ============================================================================

// RTC FAST SRAM for Method 1 (fast, but can freeze at low temps)
#define RTC_SRAM_BASE_ADDR    0x3FF80400   // Skip first 1KB used by bootloader
#define RTC_SRAM_SIZE         4096         // 4KB for PUF

// Main SRAM2 for Method 2 (slower, but 100% reliable)
#define MAIN_SRAM_BASE_ADDR   0x3FFB0000   // SRAM2 region
#define MAIN_SRAM_SIZE        4096         // 4KB for PUF

// ============================================================================
// TIMING PARAMETERS
// ============================================================================

#define RTC_POWER_OFF_MS      10           // Capacitor discharge time
#define DEEP_SLEEP_TIME_MS    100          // Deep sleep duration
#define FREEZE_HW_THRESHOLD   0.485f       // 48.5% Hamming weight freeze detection

// ============================================================================
// PUF PARAMETERS
// ============================================================================

#define PUF_RESPONSE_LEN       32          // 32-byte PUF response (256 bits)
#define SRAM_SIZE              512         // SRAM sampling size
#define NUM_ENROLLMENT_SAMPLES 20          // Number of samples for enrollment
#define ECC_NUM_SAMPLES        7           // Number of samples for ECC reconstruction

// ============================================================================
// PUF STATE
// ============================================================================

typedef enum {
    PUF_STATE_UNINITIALIZED = 0,
    PUF_STATE_ENROLLED = 1,
    PUF_STATE_RESPONSE_READY = 2
} puf_state_t;

// ============================================================================
// POWER CONTROL METHODS
// ============================================================================

typedef enum {
    PUF_METHOD_RTC_SRAM = 0,
    PUF_METHOD_DEEP_SLEEP = 1,
    PUF_METHOD_COMBINED = 2
} puf_power_method_t;

// ============================================================================
// ENROLLMENT DATA STRUCTURE
// ============================================================================

typedef struct {
    uint32_t magic;                                  // Magic number for validation
    uint16_t stable_bit_count;                       // Number of stable bits found
    uint16_t stable_bit_indices[PUF_RESPONSE_LEN * 8]; // Indices of stable bits
    uint8_t helper_data[PUF_RESPONSE_LEN];           // Helper data for reconstruction
    puf_power_method_t method;                       // Power control method used
    float hamming_weight_ref;                        // Reference HW for freeze detection
    uint8_t ecc_params[16];                          // ECC parameters (reserved)
} puf_enrollment_data_t;

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

extern uint8_t PUF_RESPONSE[PUF_RESPONSE_LEN];  // Global PUF response buffer
extern puf_state_t PUF_STATE;                    // Current PUF state

// ============================================================================
// CORE PUF FUNCTIONS
// ============================================================================

esp_err_t puflib_init(void);
esp_err_t enroll_puf(void);
bool get_puf_response(void);
void clean_puf_response(void);

// ============================================================================
// ZERO-STORED-KEY ARCHITECTURE FUNCTIONS
// ============================================================================

/**
 * @brief Extract raw SRAM and derive deterministic seed (NO ENROLLMENT)
 * 
 * This function extracts raw SRAM PUF on every boot and derives a 256-bit seed.
 * No helper data or enrollment information is stored in NVS.
 * 
 * Process:
 * 1. Extract SRAM multiple times (majority voting for stability)
 * 2. Hash entire SRAM region with SHA-256
 * 3. Return 256-bit seed
 * 
 * @param seed_out Output buffer for 32-byte (256-bit) seed
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t derive_device_seed_simple(uint8_t seed_out[32]);

/**
 * @brief Secure memory zeroization (compiler-resistant)
 * @param ptr Pointer to memory to zero
 * @param len Length of memory
 */
void secure_zeroize(void* ptr, size_t len);

/**
 * @brief Extract raw SRAM with majority voting for stability
 * @param output Buffer for stabilized SRAM output
 * @param size Size of output buffer
 * @param num_samples Number of samples for majority voting (recommend 5-7)
 * @return ESP_OK on success
 */
esp_err_t extract_raw_sram_majority(uint8_t* output, size_t size, int num_samples);


// ============================================================================
// HARDWARE PUF POWER CONTROL
// ============================================================================

esp_err_t rtc_sram_power_down(void);
esp_err_t rtc_sram_power_up(void);
void read_rtc_sram(uint8_t* buffer, size_t size);

esp_err_t deep_sleep_puf_init(void);
void deep_sleep_wake_stub(void);
void read_deep_sleep_sram(uint8_t* buffer, size_t size);

bool detect_freeze(const uint8_t* sample, size_t size, float* hw_out);

// ============================================================================
// NVS STORAGE HELPERS
// ============================================================================

esp_err_t store_enrollment_data(puf_enrollment_data_t* data);
esp_err_t load_enrollment_data(puf_enrollment_data_t* data);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void print_hex(const char* label, uint8_t* data, size_t length);
void build_mac_nvs_key(char* key_out, size_t len);

// ============================================================================
// HARDWARE PUF TEST FUNCTIONS
// ============================================================================

void test_hardware_puf(void);
void test_puf_enrollment_reconstruction(void);
void test_freeze_detection(void);

#endif // PUF_LIB_H
