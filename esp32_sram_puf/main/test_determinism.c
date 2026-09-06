#include "test_determinism.h"
#include "puf_lib.h"
#include "kyber_key_agreement.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

static const char* TAG = "TEST_DET";

// NVS key for storing reference public key
#define NVS_NAMESPACE "test_ns"
#define NVS_PUBKEY_KEY "ref_pk"

esp_err_t test_seed_consistency(int num_tests) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   SEED CONSISTENCY TEST (%d runs)       ", num_tests);
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    
    uint8_t reference_seed[32];
    uint8_t current_seed[32];
    int mismatches = 0;
    
    // Get reference seed
    if (derive_device_seed_simple(reference_seed) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to derive reference seed");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Reference seed (first 16 bytes):");
    print_hex("  ", reference_seed, 16);
    ESP_LOGI(TAG, "");
    
    // Compare against N more extractions
    for (int i = 1; i < num_tests; i++) {
        ESP_LOGI(TAG, "Test %d/%d:", i + 1, num_tests);
        
        if (derive_device_seed_simple(current_seed) != ESP_OK) {
            ESP_LOGE(TAG, "  ✗ Failed to derive seed");
            mismatches++;
            continue;
        }
        
        if (memcmp(reference_seed, current_seed, 32) == 0) {
            ESP_LOGI(TAG, "  ✓ MATCH");
        } else {
            ESP_LOGE(TAG, "  ✗ MISMATCH!");
            mismatches++;
            
            // Count different bits
            int diff_bits = 0;
            for (int j = 0; j < 32; j++) {
                uint8_t xor_val = reference_seed[j] ^ current_seed[j];
                for (int bit = 0; bit < 8; bit++) {
                    if (xor_val & (1 << bit)) diff_bits++;
                }
            }
            ESP_LOGE(TAG, "  Different bits: %d / 256 (%.2f%%)", diff_bits, 100.0 * diff_bits / 256.0);
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "RESULTS: %d/%d seeds matched (%.1f%%)",
             num_tests - mismatches, num_tests, 
             100.0 * (num_tests - mismatches) / num_tests);
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "");
    
    return (mismatches == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t test_pubkey_consistency_across_boots(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   PUBLIC KEY CONSISTENCY TEST          ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    
    // Generate keypair from PUF
    uint8_t seed[32];
    uint8_t pk[KYBER_PUBLICKEY_BYTES];
    uint8_t sk[KYBER_SECRETKEY_BYTES];
    
    ESP_LOGI(TAG, "Deriving seed and generating keypair...");
    if (derive_device_seed_simple(seed) != ESP_OK) {
        return ESP_FAIL;
    }
    
    if (kyber_keygen_deterministic(seed, pk, sk) != ESP_OK) {
        secure_zeroize(seed, sizeof(seed));
        return ESP_FAIL;
    }
    
    secure_zeroize(seed, sizeof(seed));
    secure_zeroize(sk, sizeof(sk));
    
    // Open NVS
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS");
        return err;
    }
    
    // Try to read reference public key
    uint8_t ref_pk[64];  // Store first 64 bytes
    size_t required_size = 64;
    
    err = nvs_get_blob(nvs_handle, NVS_PUBKEY_KEY, ref_pk, &required_size);
    
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // First run - store public key
        ESP_LOGI(TAG, "First run - storing reference public key");
        err = nvs_set_blob(nvs_handle, NVS_PUBKEY_KEY, pk, 64);
        if (err == ESP_OK) {
            err = nvs_commit(nvs_handle);
        }
        nvs_close(nvs_handle);
        
        ESP_LOGI(TAG, "Reference public key stored (first 32 bytes):");  
        print_hex("  ", pk, 32);
        ESP_LOGI(TAG, "");
        ESP_LOGI(TAG, "✓ Reboot the device to test consistency");
        ESP_LOGI(TAG, "");
        
        return ESP_OK;
    } else if (err == ESP_OK) {
        // Subsequent run - compare
        nvs_close(nvs_handle);
        
        ESP_LOGI(TAG, "Comparing with reference public key...");
        
        if (memcmp(ref_pk, pk, 64) == 0) {
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
            ESP_LOGI(TAG, "║   ✓✓✓ PUBLIC KEY MATCHES! ✓✓✓         ║");
            ESP_LOGI(TAG, "║   Deterministic generation works!      ║");
            ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
            ESP_LOGI(TAG, "");
            
            return ESP_OK;
        } else {
            ESP_LOGE(TAG, "");
            ESP_LOGE(TAG, "╔════════════════════════════════════════╗");
            ESP_LOGE(TAG, "║   ✗✗✗ PUBLIC KEY MISMATCH! ✗✗✗        ║");
            ESP_LOGE(TAG, "║   PUF entropy not stable enough!       ║");
            ESP_LOGE(TAG, "╚════════════════════════════════════════╝");
            ESP_LOGE(TAG, "");
            
            // Count different bits
            int diff_bits = 0;
            for (int i = 0; i < 64; i++) {
                uint8_t xor_val = ref_pk[i] ^ pk[i];
                for (int bit = 0; bit < 8; bit++) {
                    if (xor_val & (1 << bit)) diff_bits++;
                }
            }
            ESP_LOGE(TAG, "Different bits: %d / 512 (%.2f%%)", 
                     diff_bits, 100.0 * diff_bits / 512.0);
            
            return ESP_FAIL;
        }
    } else {
        nvs_close(nvs_handle);
        ESP_LOGE(TAG, "NVS error: %d", err);
        return err;
    }
}

void log_performance_metrics(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║   PERFORMANCE METRICS (FOR PAPER)      ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    
    uint64_t total_start = esp_timer_get_time();
    
    // Measure PUF extraction + seed derivation
    uint64_t start = esp_timer_get_time();
    uint8_t seed[32];
    esp_err_t ret = derive_device_seed_simple(seed);
    uint64_t seed_time = esp_timer_get_time() - start;
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Seed derivation failed");
        return;
    }
    
    // Measure Kyber keygen
    start = esp_timer_get_time();
    uint8_t pk[KY BER_PUBLICKEY_BYTES];
    uint8_t sk[KYBER_SECRETKEY_BYTES];
    ret = kyber_keygen_deterministic(seed, pk, sk);
    uint64_t keygen_time = esp_timer_get_time() - start;
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Keygen failed");
        secure_zeroize(seed, sizeof(seed));
        return;
    }
    
    uint64_t total_time = esp_timer_get_time() - total_start;
    
    // Clean up
    secure_zeroize(seed, sizeof(seed));
    secure_zeroize(sk, sizeof(sk));
    
    // Log results
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║ Metric             │ Time (µs) │  (ms) ║");
    ESP_LOGI(TAG, "╠════════════════════╪═══════════╪═══════╣");
    ESP_LOGI(TAG, "║ PUF → Seed         │ %8llu  │ %5.2f ║", seed_time, seed_time / 1000.0);
    ESP_LOGI(TAG, "║ Kyber Keygen       │ %8llu  │ %5.2f ║", keygen_time, keygen_time / 1000.0);
    ESP_LOGI(TAG, "║ TOTAL BOOT         │ %8llu  │ %5.2f ║", total_time, total_time / 1000.0);
    ESP_LOGI(TAG, "╚════════════════════╧═══════════╧═══════╝");
    ESP_LOGI(TAG, "");
    
    // Memory info
    ESP_LOGI(TAG, "Memory Usage:");
    ESP_LOGI(TAG, "  Heap free: %lu bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "  Min heap: %lu bytes", esp_get_minimum_free_heap_size());
    ESP_LOGI(TAG, "");
}

void save_metrics_to_csv(int trial_number) {
    // Future: implement CSV export to SD card for batch testing
    ESP_LOGI(TAG, "CSV export not yet implemented - use log output");
}
