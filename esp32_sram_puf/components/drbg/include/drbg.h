#ifndef DRBG_H
#define DRBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * @brief Deterministic Random Bit Generator (DRBG)
 * 
 * Counter-based SHA-256 DRBG for deterministic key generation.
 * Same seed always produces same output sequence.
 * 
 * Design: output = SHA256(seed || counter)
 * Increments counter for each 32-byte block.
 */

#define DRBG_SEED_LEN 32  // 256 bits

typedef struct {
    uint8_t seed[DRBG_SEED_LEN];
    uint64_t counter;
    bool initialized;
} drbg_ctx_t;

/**
 * @brief Initialize DRBG with seed
 * @param ctx DRBG context
 * @param seed 32-byte seed (from PUF)
 * @return ESP_OK on success
 */
esp_err_t drbg_init(drbg_ctx_t* ctx, const uint8_t seed[DRBG_SEED_LEN]);

/**
 * @brief Generate deterministic random bytes
 * @param ctx DRBG context
 * @param output Buffer for random bytes
 * @param len Number of bytes to generate
 * @return ESP_OK on success
 */
esp_err_t drbg_generate(drbg_ctx_t* ctx, uint8_t* output, size_t len);

/**
 * @brief Clean up DRBG context (zeroize sensitive data)
 * @param ctx DRBG context
 */
void drbg_cleanup(drbg_ctx_t* ctx);

/**
 * @brief Get random bytes (wrapper for compatibility)
 * @param ctx DRBG context
 * @return 32-bit random value
 */
uint32_t drbg_random(drbg_ctx_t* ctx);

#endif // DRBG_H
