/**
 * @file test_determinism.h
 * @brief Testing utilities for zero-stored-key architecture
 * 
 * Tests to verify:
 * 1. Public key consistency across reboots
 * 2. 200-cycle authentication test
 * 3. Performance metrics collection
 */

#ifndef TEST_DETERMINISM_H
#define TEST_DETERMINISM_H

#include <stdint.h>
#include "esp_err.h"

/**
 * @brief Test seed consistency across multiple PUF extractions
 * 
 * Extracts PUF and derives seed N times, compares all seeds.
 * This tests the stability of raw SRAM extraction.
 * 
 * @param num_tests Number of test iterations
 * @return ESP_OK if all seeds match, ESP_FAIL otherwise
 */
esp_err_t test_seed_consistency(int num_tests);

/**
 * @brief Test Kyber public key consistency
 * 
 * This test should be run after 20 reboots:
 * - Derives seed from PUF
 * - Generates Kyber keypair
 * - Stores first 64 bytes of public key to file
 * - On subsequent runs, compares with stored value
 * 
 * Usage:
 * 1. Flash firmware
 * 2. Reboot 20 times
 * 3. Check logs for consistency report
 * 
 * @return ESP_OK if consistent, ESP_FAIL otherwise
 */
esp_err_t test_pubkey_consistency_across_boots(void);

/**
 * @brief Log performance metrics for research paper
 * 
 * Measures and logs:
 * - PUF extraction time
 * - Seed derivation time
 * - DRBG init time
 * - Kyber keygen time
 * - Total boot time
 * - Memory usage
 */
void log_performance_metrics(void);

/**
 * @brief Save metrics to CSV file (if SD card available)
 * @param trial_number Current trial number
 */
void save_metrics_to_csv(int trial_number);

#endif // TEST_DETERMINISM_H
