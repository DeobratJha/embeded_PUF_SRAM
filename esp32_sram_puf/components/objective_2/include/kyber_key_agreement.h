#ifndef KYBER_KEY_AGREEMENT_H
#define KYBER_KEY_AGREEMENT_H

#include <stdint.h>
#include "esp_err.h"
#include "api.h"  // CRITICAL: Include Kyber API for CRYPTO_ constants

/* Kyber768 sizes from api.h */
#define KYBER_PUBLICKEY_BYTES   CRYPTO_PUBLICKEYBYTES    // 1184 bytes
#define KYBER_SECRETKEY_BYTES   CRYPTO_SECRETKEYBYTES    // 2400 bytes
#define KYBER_CIPHERTEXT_BYTES  CRYPTO_CIPHERTEXTBYTES   // 1088 bytes
#define KYBER_SHAREDSECRET_BYTES CRYPTO_BYTES             // 32 bytes

/* session container (example) */
typedef struct {
    uint8_t enc_key[32];   // AES-256 key (example)
    uint8_t mac_key[32];   // additional key if needed
} kyber_session_t;

/* API */
esp_err_t kyber_init(void);
esp_err_t kyber_keygen(uint8_t *pk_out, uint8_t *sk_out); /* GCC - normal random */

/**
 * @brief Deterministic Kyber key generation from PUF-derived seed (UAV ONLY)
 * 
 * This function generates a Kyber keypair deterministically from a 256-bit seed.
 * The same seed always produces the same keypair.
 * 
 * @param seed 32-byte (256-bit) seed from PUF
 * @param pk_out Public key output (1600 bytes)
 * @param sk_out Secret key output (1632 bytes)
 * @return ESP_OK on success
 */
esp_err_t kyber_keygen_deterministic(const uint8_t seed[32], uint8_t *pk_out, uint8_t *sk_out);

esp_err_t kyber_encaps(const uint8_t *pk, uint8_t *ct_out, uint8_t *ss_out); /* UAV */
esp_err_t kyber_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out); /* GCC */
esp_err_t kyber_derive_session_keys(const uint8_t *shared_secret, kyber_session_t *session);
void kyber_secure_memzero(void *buf, size_t len);

#endif // KYBER_KEY_AGREEMENT_H

