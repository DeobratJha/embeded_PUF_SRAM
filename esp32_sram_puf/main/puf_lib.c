#include "puf_lib.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include "esp_mac.h"
#include "esp_task_wdt.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/rtc.h"
#include "esp_sleep.h"
#include "esp_rom_sys.h"
#include "mbedtls/sha256.h"


static const char* TAG = "PUF_LIB";

// Magic number for enrollment data validation
#define PUF_ENROLLMENT_MAGIC 0x50554631

// Global PUF response buffer
uint8_t PUF_RESPONSE[PUF_RESPONSE_LEN];
puf_state_t PUF_STATE = PUF_STATE_UNINITIALIZED;

// Protected buffers for deep sleep method (survives reboot)
RTC_NOINIT_ATTR static uint8_t deep_sleep_puf_buffer[MAIN_SRAM_SIZE];
RTC_NOINIT_ATTR static bool deep_sleep_puf_ready;

// ============================================================================
// HARDWARE METHOD 1: RTC SRAM POWER CONTROL
// ============================================================================

esp_err_t rtc_sram_power_down(void) {
    // Clear RTC memory force power-up bit
    REG_CLR_BIT(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_LSLP_MEM_FORCE_PU);

    // Power down RTC FAST memory
    REG_SET_BIT(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_LSLP_MEM_FORCE_PD);

    ESP_LOGI(TAG, "RTC SRAM powered down");

    // Wait for capacitor discharge (CRITICAL for PUF quality)
    vTaskDelay(pdMS_TO_TICKS(RTC_POWER_OFF_MS));

    return ESP_OK;
}

esp_err_t rtc_sram_power_up(void) {
    // Clear power-down bit
    REG_CLR_BIT(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_LSLP_MEM_FORCE_PD);

    // Force power-up
    REG_SET_BIT(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_LSLP_MEM_FORCE_PU);

    ESP_LOGI(TAG, "RTC SRAM powered up");

    // Small delay for power stabilization
        esp_rom_delay_us(5000);  // 5ms


    return ESP_OK;
}

void read_rtc_sram(uint8_t* buffer, size_t size) {
    // Direct memory access to RTC SRAM
    volatile uint8_t* rtc_mem = (volatile uint8_t*)RTC_SRAM_BASE_ADDR;

    for (size_t i = 0; i < size; i++) {
        buffer[i] = rtc_mem[i];
    }

    ESP_LOGI(TAG, "Read %d bytes from RTC SRAM", (int)size);
}

// ============================================================================
// HARDWARE METHOD 2: DEEP SLEEP WAKE STUB
// ============================================================================

void RTC_IRAM_ATTR deep_sleep_wake_stub(void) {
    // This code runs in RTC FAST memory immediately after wake-up
    // BEFORE the bootloader initializes SRAM

    // Copy uninitialized SRAM to protected buffer
    volatile uint8_t* sram_ptr = (volatile uint8_t*)MAIN_SRAM_BASE_ADDR;

    for (int i = 0; i < MAIN_SRAM_SIZE; i++) {
        deep_sleep_puf_buffer[i] = sram_ptr[i];
    }

    // Mark as ready
    deep_sleep_puf_ready = true;

    // Continue normal boot process
    esp_default_wake_deep_sleep();
}

esp_err_t deep_sleep_puf_init(void) {
    // Set custom wake stub
    esp_set_deep_sleep_wake_stub(&deep_sleep_wake_stub);

    ESP_LOGI(TAG, "Deep sleep wake stub configured");
    return ESP_OK;
}

void read_deep_sleep_sram(uint8_t* buffer, size_t size) {
    // Mark buffer as not ready
    deep_sleep_puf_ready = false;

    // Configure wake-up timer
    esp_sleep_enable_timer_wakeup(DEEP_SLEEP_TIME_MS * 1000);  // Convert to microseconds

    ESP_LOGI(TAG, "Entering deep sleep for PUF extraction...");

    // Enter deep sleep - THIS REBOOTS THE DEVICE
    esp_deep_sleep_start();

    // NEVER REACHES HERE - device reboots
}

// ============================================================================
// FREEZE DETECTION
// ============================================================================

bool detect_freeze(const uint8_t* sample, size_t size, float* hw_out) {
    // Calculate Hamming weight (percentage of 1 bits)
    int ones = 0;
    for (size_t i = 0; i < size; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (sample[i] & (1 << bit)) {
                ones++;
            }
        }
    }

    float hw = (float)ones / (size * 8);
    if (hw_out) *hw_out = hw;

    // Check if SRAM has frozen (low HW indicates freeze)
    bool is_frozen = (hw < FREEZE_HW_THRESHOLD);

    if (is_frozen) {
        ESP_LOGW(TAG, "SRAM FREEZE DETECTED (HW=%.3f < %.3f)",
                 hw, FREEZE_HW_THRESHOLD);
    }

    return is_frozen;
}

// ============================================================================
// HARDWARE SAMPLE GENERATION (TRUE PUF)
// ============================================================================

static void generate_random_sample(uint8_t* buffer, size_t size) {
    // Power cycle RTC SRAM
    rtc_sram_power_down();
    rtc_sram_power_up();

    // Read uninitialized SRAM - THIS IS THE TRUE HARDWARE PUF!
    read_rtc_sram(buffer, size);

    // Calculate Hamming weight for diagnostics
    int ones = 0;
    for (size_t i = 0; i < size; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (buffer[i] & (1 << bit)) ones++;
        }
    }
    float hw = (float)ones / (size * 8);
    ESP_LOGI(TAG, "Sample HW: %.3f", hw);
}

// ============================================================================
// ECC RECONSTRUCTION
// ============================================================================

static void apply_ecc_reconstruction(puf_enrollment_data_t* data,
                                     uint8_t samples[ECC_NUM_SAMPLES][SRAM_SIZE]) {
    // Clear PUF response
    memset(PUF_RESPONSE, 0, PUF_RESPONSE_LEN);

    // For each stable bit, apply majority voting
    for (uint16_t i = 0; i < data->stable_bit_count; i++) {
        uint16_t bit = data->stable_bit_indices[i];
        size_t byte_idx = bit / 8;
        uint8_t bit_mask = 1 << (bit % 8);

        // Count how many samples have this bit set
        int ones = 0;
        for (int s = 0; s < ECC_NUM_SAMPLES; s++) {
            if (samples[s][byte_idx] & bit_mask) {
                ones++;
            }
        }

        // Majority vote: if >50% samples have bit=1, set it in response
        if (ones > ECC_NUM_SAMPLES / 2) {
            PUF_RESPONSE[i / 8] |= (1 << (i % 8));
        }
    }

    PUF_STATE = PUF_STATE_RESPONSE_READY;
    ESP_LOGI(TAG, "PUF response reconstructed (%d stable bits)",
             data->stable_bit_count);
}

// ============================================================================
// PUF RESPONSE RECONSTRUCTION (COMBINED METHOD)
// ============================================================================

bool get_puf_response(void) {
    ESP_LOGI(TAG, "Reconstructing PUF response...");

    // Load enrollment data
    puf_enrollment_data_t data;
    if (load_enrollment_data(&data) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load enrollment data");
        return false;
    }

    // Check if we're coming from deep sleep
    if (deep_sleep_puf_ready) {
        ESP_LOGI(TAG, "Using deep sleep PUF data");

        // Deep sleep buffer is already filled by wake stub
        uint8_t samples[ECC_NUM_SAMPLES][SRAM_SIZE];

        // Use deep sleep buffer as first sample
        memcpy(samples[0], deep_sleep_puf_buffer, SRAM_SIZE);

        // Collect additional samples using RTC method
        for (int i = 1; i < ECC_NUM_SAMPLES; i++) {
            generate_random_sample(samples[i], SRAM_SIZE);
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        // Apply ECC (majority voting)
        apply_ecc_reconstruction(&data, samples);

        deep_sleep_puf_ready = false;
        return true;
    }

    // Try RTC SRAM method first (fast path)
    ESP_LOGI(TAG, "Attempting RTC SRAM method...");

    uint8_t samples[ECC_NUM_SAMPLES][SRAM_SIZE];

    // Collect ECC samples
    for (int i = 0; i < ECC_NUM_SAMPLES; i++) {
        generate_random_sample(samples[i], SRAM_SIZE);
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    // Check for freeze condition
    float hw;
    bool is_frozen = detect_freeze(samples[0], SRAM_SIZE, &hw);

    if (is_frozen) {
        ESP_LOGW(TAG, "RTC SRAM frozen - switching to deep sleep method");

        // Trigger deep sleep - THIS WILL REBOOT
        read_deep_sleep_sram(NULL, 0);

        // Never reaches here
        return false;
    }

    // RTC method successful - apply ECC
    ESP_LOGI(TAG, "RTC SRAM method successful (HW=%.3f)", hw);
    apply_ecc_reconstruction(&data, samples);

    return true;
}

// ============================================================================
// PUF ENROLLMENT
// ============================================================================

esp_err_t enroll_puf(void) {
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   HARDWARE PUF ENROLLMENT");
    ESP_LOGI(TAG, "═══════════════════════════════════════");

    // Initialize deep sleep wake stub
    deep_sleep_puf_init();

    puf_enrollment_data_t data;
    memset(&data, 0, sizeof(data));
    data.magic = PUF_ENROLLMENT_MAGIC;
    data.method = PUF_METHOD_COMBINED;

    // Collect hardware samples
    ESP_LOGI(TAG, "Collecting %d hardware samples...", NUM_ENROLLMENT_SAMPLES);

    static uint8_t samples[NUM_ENROLLMENT_SAMPLES][SRAM_SIZE];

    for (int i = 0; i < NUM_ENROLLMENT_SAMPLES; i++) {
        generate_random_sample(samples[i], SRAM_SIZE);

        // Show progress
        if ((i + 1) % 5 == 0) {
            ESP_LOGI(TAG, "  Sample %d/%d complete", i + 1, NUM_ENROLLMENT_SAMPLES);
        }

        vTaskDelay(pdMS_TO_TICKS(50));  // Wait between samples
    }

    // Analyze bit stability
    ESP_LOGI(TAG, "Analyzing bit stability...");

    uint16_t total_stable = 0;

    for (size_t byte_idx = 0; byte_idx < SRAM_SIZE; byte_idx++) {
        for (int b = 0; b < 8; b++) {
            // Count how many samples have this bit set
            int ones = 0;
            for (size_t s = 0; s < NUM_ENROLLMENT_SAMPLES; s++) {
                if (samples[s][byte_idx] & (1 << b)) ones++;
            }

            float p = (float)ones / NUM_ENROLLMENT_SAMPLES;

            // Bit is stable if it's consistently 0 (<15%) or 1 (>85%)
            if (p < 0.15f || p > 0.85f) {
                if (total_stable < PUF_RESPONSE_LEN * 8) {
                    data.stable_bit_indices[data.stable_bit_count++] =
                        byte_idx * 8 + b;
                    total_stable++;
                }
            }
        }
    }

    ESP_LOGI(TAG, "Found %d stable bits (%.1f%%)",
             total_stable, 100.0f * total_stable / (SRAM_SIZE * 8));

    if (total_stable < 256) {
        ESP_LOGE(TAG, "Insufficient stable bits for PUF!");
        return ESP_FAIL;
    }

    // Generate helper data from stable bits
    uint8_t helper[PUF_RESPONSE_LEN] = {0};
    for (uint16_t i = 0; i < data.stable_bit_count && i < PUF_RESPONSE_LEN * 8; i++) {
        uint16_t bit = data.stable_bit_indices[i];

        // Use first sample as reference
        if (samples[0][bit / 8] & (1 << (bit % 8))) {
            helper[i / 8] |= (1 << (i % 8));
        }
    }
    memcpy(data.helper_data, helper, PUF_RESPONSE_LEN);

    // Calculate reference Hamming weight for freeze detection
    int ones = 0;
    for (size_t i = 0; i < SRAM_SIZE; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (samples[0][i] & (1 << bit)) ones++;
        }
    }
    data.hamming_weight_ref = (float)ones / (SRAM_SIZE * 8);

    // Store to NVS
    esp_err_t ret = store_enrollment_data(&data);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store enrollment data");
        return ret;
    }

    PUF_STATE = PUF_STATE_ENROLLED;

    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   ✓ HARDWARE PUF ENROLLED");
    ESP_LOGI(TAG, "   Stable bits: %d", data.stable_bit_count);
    ESP_LOGI(TAG, "   Reference HW: %.3f", data.hamming_weight_ref);
    ESP_LOGI(TAG, "═══════════════════════════════════════");

    return ESP_OK;
}

// ============================================================================
// NVS STORAGE
// ============================================================================

void build_mac_nvs_key(char* key_out, size_t len) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(key_out, len, "PUF_%02X%02X%02X", mac[3], mac[4], mac[5]);
}

esp_err_t store_enrollment_data(puf_enrollment_data_t* data) {
    nvs_handle_t handle;
    char nvs_key[32];

    build_mac_nvs_key(nvs_key, sizeof(nvs_key));

    esp_err_t err = nvs_open("puf_storage", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    err = nvs_set_blob(handle, nvs_key, data, sizeof(puf_enrollment_data_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

esp_err_t load_enrollment_data(puf_enrollment_data_t* data) {
    nvs_handle_t handle;
    char nvs_key[32];

    build_mac_nvs_key(nvs_key, sizeof(nvs_key));

    esp_err_t err = nvs_open("puf_storage", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;

    size_t required_size = sizeof(puf_enrollment_data_t);
    err = nvs_get_blob(handle, nvs_key, data, &required_size);

    nvs_close(handle);

    if (err == ESP_OK && data->magic != PUF_ENROLLMENT_MAGIC) {
        return ESP_FAIL;
    }

    return err;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

void print_hex(const char* label, uint8_t* data, size_t length) {
    printf("%s", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    if (length % 16 != 0) printf("\n");
}

void clean_puf_response(void) {
    memset(PUF_RESPONSE, 0, PUF_RESPONSE_LEN);
    PUF_STATE = PUF_STATE_ENROLLED;
}

esp_err_t puflib_init(void) {
    ESP_LOGI(TAG, "Initializing PUF library...");

    // Check if already enrolled
    puf_enrollment_data_t data;
    if (load_enrollment_data(&data) == ESP_OK) {
        PUF_STATE = PUF_STATE_ENROLLED;
        ESP_LOGI(TAG, "✓ PUF already enrolled");
    } else {
        PUF_STATE = PUF_STATE_UNINITIALIZED;
        ESP_LOGI(TAG, "PUF not enrolled yet");
    }

    return ESP_OK;
}

// ============================================================================
// HARDWARE PUF TEST FUNCTIONS
// ============================================================================

void test_hardware_puf(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║        HARDWARE PUF TEST               ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    uint8_t sample1[512], sample2[512];

    ESP_LOGI(TAG, "Generating sample 1...");
    generate_random_sample(sample1, 512);
    vTaskDelay(pdMS_TO_TICKS(100));

    ESP_LOGI(TAG, "Generating sample 2...");
    generate_random_sample(sample2, 512);

    // Calculate bit similarity (should be 80-95% for hardware PUF)
    int matches = 0;
    for (int i = 0; i < 512 * 8; i++) {
        bool bit1 = (sample1[i/8] >> (i%8)) & 1;
        bool bit2 = (sample2[i/8] >> (i%8)) & 1;
        if (bit1 == bit2) matches++;
    }

    float similarity = 100.0f * matches / (512 * 8);
    ESP_LOGI(TAG, "Bit similarity: %.2f%% (expect 80-95%% for hardware)", similarity);

    if (similarity >= 80.0f && similarity <= 95.0f) {
        ESP_LOGI(TAG, "✓ Hardware PUF test PASSED");
    } else if (similarity > 99.0f) {
        ESP_LOGW(TAG, "⚠ Still using simulated PUF (similarity too high)");
    } else {
        ESP_LOGE(TAG, "✗ Hardware PUF test FAILED");
    }

    ESP_LOGI(TAG, "");
}

void test_puf_enrollment_reconstruction(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║    PUF ENROLLMENT & RECONSTRUCTION     ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    // Test reconstruction 5 times and compare
    uint8_t ref_response[PUF_RESPONSE_LEN];
    bool first = true;
    int successful_reconstructions = 0;

    for (int i = 0; i < 5; i++) {
        ESP_LOGI(TAG, "Reconstruction attempt %d/5...", i + 1);

        if (!get_puf_response()) {
            ESP_LOGE(TAG, "✗ Reconstruction %d failed", i + 1);
            continue;
        }

        if (first) {
            memcpy(ref_response, PUF_RESPONSE, PUF_RESPONSE_LEN);
            first = false;
            successful_reconstructions++;
            ESP_LOGI(TAG, "✓ Reference response established");
        } else {
            // Compare with reference
            int errors = 0;
            for (int j = 0; j < PUF_RESPONSE_LEN; j++) {
                for (int bit = 0; bit < 8; bit++) {
                    bool ref_bit = (ref_response[j] >> bit) & 1;
                    bool cur_bit = (PUF_RESPONSE[j] >> bit) & 1;
                    if (ref_bit != cur_bit) errors++;
                }
            }

            float error_rate = 100.0f * errors / (PUF_RESPONSE_LEN * 8);
            ESP_LOGI(TAG, "Reconstruction %d: %.2f%% error", i + 1, error_rate);

            if (error_rate == 0.0f) {
                successful_reconstructions++;
            }
        }

        clean_puf_response();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    ESP_LOGI(TAG, "Success rate: %d/5 (%.0f%%)",
             successful_reconstructions,
             100.0f * successful_reconstructions / 5);

    if (successful_reconstructions == 5) {
        ESP_LOGI(TAG, "✓ PUF reconstruction test PASSED");
    } else {
        ESP_LOGW(TAG, "⚠ PUF reconstruction partially successful");
    }

    ESP_LOGI(TAG, "");
}

void test_freeze_detection(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║        FREEZE DETECTION TEST           ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    uint8_t sample[SRAM_SIZE];

    for (int i = 0; i < 3; i++) {
        ESP_LOGI(TAG, "Test sample %d/3:", i + 1);
        generate_random_sample(sample, SRAM_SIZE);

        float hw;
        bool is_frozen = detect_freeze(sample, SRAM_SIZE, &hw);

        ESP_LOGI(TAG, "  HW=%.3f, Frozen=%s", hw, is_frozen ? "YES" : "NO");

        if (is_frozen) {
            ESP_LOGW(TAG, "  → Would trigger deep sleep fallback");
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "");
}

// ============================================================================
// ZERO-STORED-KEY ARCHITECTURE IMPLEMENTATION
// ============================================================================

void secure_zeroize(void* ptr, size_t len) {
    if (!ptr) return;
    
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

esp_err_t extract_raw_sram_majority(uint8_t* output, size_t size, int num_samples) {
    if (!output || size == 0 || num_samples < 3) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Extracting SRAM with %d samples for majority voting...", num_samples);
    
    // Allocate samples buffer
    static uint8_t samples[7][SRAM_SIZE];  // Max 7 samples
    if (num_samples > 7) num_samples = 7;
    if (size > SRAM_SIZE) size = SRAM_SIZE;
    
    // Collect samples
    for (int i = 0; i < num_samples; i++) {
        generate_random_sample(samples[i], size);
        vTaskDelay(pdMS_TO_TICKS(5));  // Small delay between samples
    }
    
    // Majority voting for each bit
    memset(output, 0, size);
    
    for (size_t byte_idx = 0; byte_idx < size; byte_idx++) {
        for (int bit = 0; bit < 8; bit++) {
            int ones = 0;
            
            // Count how many samples have this bit set
            for (int s = 0; s < num_samples; s++) {
                if (samples[s][byte_idx] & (1 << bit)) {
                    ones++;
                }
            }
            
            // Majority vote
            if (ones > num_samples / 2) {
                output[byte_idx] |= (1 << bit);
            }
        }
    }
    
    ESP_LOGI(TAG, "✓ SRAM extraction complete with majority voting");
    return ESP_OK;
}

esp_err_t derive_device_seed_simple(uint8_t seed_out[32]) {
    if (!seed_out) {
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   DERIVING DEVICE SEED FROM PUF");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    
    uint64_t start_time = esp_timer_get_time();
    
    // Step 1: Extract raw SRAM with majority voting (5 samples)
    uint8_t raw_sram[SRAM_SIZE];
    esp_err_t ret = extract_raw_sram_majority(raw_sram, SRAM_SIZE, 5);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to extract SRAM");
        return ret;
    }
    
    uint64_t extraction_time = esp_timer_get_time() - start_time;
    
    // Step 2: Hash entire SRAM region to derive seed
    uint64_t hash_start = esp_timer_get_time();
    
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, raw_sram, SRAM_SIZE);
    mbedtls_sha256_finish(&ctx, seed_out);
    mbedtls_sha256_free(&ctx);
    
    uint64_t hash_time = esp_timer_get_time() - hash_start;
    
    // Zeroize raw SRAM buffer
    secure_zeroize(raw_sram, sizeof(raw_sram));
    
    uint64_t total_time = esp_timer_get_time() - start_time;
    
    ESP_LOGI(TAG, "✓ Device seed derived successfully");
    ESP_LOGI(TAG, "Performance Metrics:");
    ESP_LOGI(TAG, "  SRAM extraction: %llu µs", extraction_time);
    ESP_LOGI(TAG, "  SHA-256 hashing: %llu µs", hash_time);
    ESP_LOGI(TAG, "  Total time: %llu µs (%.2f ms)", total_time, total_time / 1000.0);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Seed (first 16 bytes):");
    print_hex("  ", seed_out, 16);
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "");
    
    return ESP_OK;
}

