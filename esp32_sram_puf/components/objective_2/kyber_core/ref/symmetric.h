#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "fips202.h"  // Real FIPS202 implementation

// XOF definitions
typedef keccak_state xof_state;
#define XOF_BLOCKBYTES SHAKE128_RATE

// Kyber wrapper functions - declare them here (from symmetric-shake.c)
void kyber_shake128_absorb(keccak_state *state, const uint8_t seed[32], uint8_t x, uint8_t y);
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[32], uint8_t nonce);
void kyber_shake256_rkprf(uint8_t out[32], const uint8_t key[32], const uint8_t input[1088]);

// Hash function macros
#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)

// XOF macros
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

// PRF macros
#define prf(OUT, OUTLEN, KEY, NONCE) kyber_shake256_prf(OUT, OUTLEN, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

#endif
