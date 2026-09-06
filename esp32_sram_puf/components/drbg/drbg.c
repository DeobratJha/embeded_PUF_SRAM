#include "drbg.h"
#include "mbedtls/sha256.h"
#include "esp_log.h"
#include <string.h>

static const char* TAG = "DRBG";

esp_err_t drbg_init(drbg_ctx_t* ctx, const uint8_t seed[DRBG_SEED_LEN]) {
    if (!ctx || !seed) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(ctx->seed, seed, DRBG_SEED_LEN);
    ctx->counter = 0;
    ctx->initialized = true;

    ESP_LOGI(TAG, "DRBG initialized with seed");
    return ESP_OK;
}

esp_err_t drbg_generate(drbg_ctx_t* ctx, uint8_t* output, size_t len) {
    if (!ctx || !ctx->initialized || !output) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t remaining = len;
    size_t offset = 0;

    while (remaining > 0) {
        // Prepare input: seed || counter (8 bytes)
        uint8_t input[DRBG_SEED_LEN + 8];
        memcpy(input, ctx->seed, DRBG_SEED_LEN);
        
        // Append counter in big-endian
        for (int i = 7; i >= 0; i--) {
            input[DRBG_SEED_LEN + i] = (ctx->counter >> (8 * (7 - i))) & 0xFF;
        }

        // Hash: SHA256(seed || counter)
        uint8_t hash[32];
        mbedtls_sha256_context sha_ctx;
        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts(&sha_ctx, 0);
        mbedtls_sha256_update(&sha_ctx, input, sizeof(input));
        mbedtls_sha256_finish(&sha_ctx, hash);
        mbedtls_sha256_free(&sha_ctx);

        // Copy to output
        size_t to_copy = (remaining < 32) ? remaining : 32;
        memcpy(output + offset, hash, to_copy);

        offset += to_copy;
        remaining -= to_copy;
        ctx->counter++;
    }

    return ESP_OK;
}

void drbg_cleanup(drbg_ctx_t* ctx) {
    if (ctx) {
        // Secure zeroization
        volatile uint8_t* p = (volatile uint8_t*)ctx;
        for (size_t i = 0; i < sizeof(drbg_ctx_t); i++) {
            p[i] = 0;
        }
        ctx->initialized = false;
    }
}

uint32_t drbg_random(drbg_ctx_t* ctx) {
    uint32_t value;
    if (drbg_generate(ctx, (uint8_t*)&value, sizeof(value)) != ESP_OK) {
        ESP_LOGE(TAG, "DRBG generation failed");
        return 0;
    }
    return value;
}
