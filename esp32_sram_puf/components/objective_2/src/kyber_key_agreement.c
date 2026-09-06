#include "kyber_key_agreement.h"
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "drbg.h"

/* Include Kyber API header from ref/ (api.h) */
#include "api.h"     /* defines CRYPTO_* sizes and functions */
#include "kem.h"     /* if your kyber ref uses kem.h */

/* NOTE: some ref ports name functions crypto_kem_keypair, crypto_kem_enc, crypto_kem_dec */
extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// Global DRBG context for deterministic key generation (UAV only)
static drbg_ctx_t g_drbg_ctx = {0};
static bool g_drbg_active = false;

static const char *TAG = "KYBER_WRAPPER";

esp_err_t kyber_init(void)
{
    ESP_LOGI(TAG, "Kyber init");
    /* if using randombytes that needs init, do it here; otherwise noop */
    return ESP_OK;
}

esp_err_t kyber_keygen(uint8_t *pk_out, uint8_t *sk_out)
{
    int r = crypto_kem_keypair(pk_out, sk_out);
    return (r == 0) ? ESP_OK : ESP_FAIL;
}

/**
 * @brief Override randombytes for deterministic generation
 * 
 * This function is called by Kyber internally for randomness.
 * When g_drbg_active is true, we use DRBG instead of hardware RNG.
 * 
 * IMPORTANT: This MUST be defined with __attribute__((used)) to ensure
 * the linker uses THIS version instead of any weak symbols from Kyber.
 */
__attribute__((used))
void randombytes(uint8_t *out, size_t outlen) {
    static int call_count = 0;
    call_count++;
    
    if (g_drbg_active && g_drbg_ctx.initialized) {
        // Use deterministic DRBG
        if (call_count <= 10) {  // Log first 10 calls to see if this is actually being used
            ESP_LOGI(TAG, "🔵 OUR randombytes() call #%d: DRBG mode, %zu bytes", call_count, outlen);
        }
        esp_err_t ret = drbg_generate(&g_drbg_ctx, out, outlen);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "DRBG generate failed!");
            // Fill with zeros on error
            memset(out, 0, outlen);
        } else if (call_count <= 3 && outlen >= 8) {
            // Log first few bytes of first 3 calls
            ESP_LOGI(TAG, "  First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X",
                     out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
        }
    } else {
        // Fall back to hardware RNG (for GCS normal operation)
        if (call_count <= 10) {
            ESP_LOGI(TAG, "🔵 OUR randombytes() call #%d: Hardware RNG, %zu bytes", call_count, outlen);
        }
        extern void esp_fill_random(void *buf, size_t len);
        esp_fill_random(out, outlen);
    }
}

esp_err_t kyber_keygen_deterministic(const uint8_t seed[32], uint8_t *pk_out, uint8_t *sk_out)
{
    if (!seed || !pk_out || !sk_out) {
        ESP_LOGE(TAG, "Invalid arguments for deterministic keygen");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "   DETERMINISTIC KYBER KEY GENERATION");
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    
    uint64_t start_time = esp_timer_get_time();
    
    // Step 1: Initialize DRBG with PUF-derived seed
    esp_err_t ret = drbg_init(&g_drbg_ctx, seed);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize DRBG");
        return ret;
    }
    
    // Step 2: Enable deterministic mode
    g_drbg_active = true;
    
    //  Step 3: Call Kyber keygen (will use randombytes -> DRBG)
    int r = crypto_kem_keypair(pk_out, sk_out);
    
    // Step 4: Disable deterministic mode
    g_drbg_active = false;
    
    // Step 5: Clean up DRBG context
    drbg_cleanup(&g_drbg_ctx);
    
    uint64_t total_time = esp_timer_get_time() - start_time;
    
    if (r != 0) {
        ESP_LOGE(TAG, "Kyber keypair generation failed");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "✓ Deterministic keypair generated");
    ESP_LOGI(TAG, "Performance:");
    ESP_LOGI(TAG, "  Keygen time: %llu µs (%.2f ms)", total_time, total_time / 1000.0);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Public key (first 32 bytes):");
    
    // Print first 32 bytes of public key for verification
    for (int i = 0; i < 32; i++) {
        if (i % 16 == 0) printf("  ");
        printf("%02X ", pk_out[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    // NEW: Also check last 32 bytes to see if key is partially populated
    ESP_LOGI(TAG, "Public key (last 32 bytes):");
    for (int i = CRYPTO_PUBLICKEYBYTES - 32; i < CRYPTO_PUBLICKEYBYTES; i++) {
        if ((i - (CRYPTO_PUBLICKEYBYTES - 32)) % 16 == 0) printf("  ");
        printf("%02X ", pk_out[i]);
        if ((i - (CRYPTO_PUBLICKEYBYTES - 32) + 1) % 16 == 0) printf("\n");
    }
    
    ESP_LOGI(TAG, "═══════════════════════════════════════");
    ESP_LOGI(TAG, "");
    
    return ESP_OK;
}

esp_err_t kyber_encaps(const uint8_t *pk, uint8_t *ct_out, uint8_t *ss_out)
{
    int r = crypto_kem_enc(ct_out, ss_out, pk);
    return (r == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t kyber_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out)
{
    int r = crypto_kem_dec(ss_out, ct, sk);
    return (r == 0) ? ESP_OK : ESP_FAIL;
}

#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"

/* Simple HKDF-SHA256 derive (example). In production, use a proper HKDF implementation. */
esp_err_t kyber_derive_session_keys(const uint8_t *shared_secret, kyber_session_t *session)
{
    /* Derive two 32-byte keys using mbedtls HMAC-SHA256 as HKDF-Expand analogue */
    /* For brevity: use mbedtls_md_hmac with salt=NULL and different info bytes */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return ESP_FAIL;

    /* Example: derive enc_key = HMAC(shared_secret, 0x01), mac_key = HMAC(shared_secret, 0x02) */
    if (mbedtls_md_hmac(md_info, shared_secret, KYBER_SHAREDSECRET_BYTES, (const unsigned char *)"\x01", 1, session->enc_key) != 0) {
        return ESP_FAIL;
    }
    if (mbedtls_md_hmac(md_info, shared_secret, KYBER_SHAREDSECRET_BYTES, (const unsigned char *)"\x02", 1, session->mac_key) != 0) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

void kyber_secure_memzero(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
}
