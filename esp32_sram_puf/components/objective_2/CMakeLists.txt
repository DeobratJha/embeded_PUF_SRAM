idf_component_register(
    SRCS
        "src/kyber_key_agreement.c"
        "kyber_core/ref/kem.c"
        "kyber_core/ref/indcpa.c"
        "kyber_core/ref/poly.c"
        "kyber_core/ref/polyvec.c"
        "kyber_core/ref/ntt.c"
        "kyber_core/ref/reduce.c"
        "kyber_core/ref/cbd.c"
        "kyber_core/ref/verify.c"
        "kyber_core/ref/symmetric-shake.c"  # Contains hash wrappers
        "kyber_core/ref/fips202.c"          # REAL Keccak/SHA3/SHAKE implementation!
        # REMOVED: "kyber_core/ref/randombytes.c"
        # We provide our own randombytes() in kyber_key_agreement.c
        # which can switch between deterministic (DRBG) and hardware RNG
    INCLUDE_DIRS
        "include"
        "kyber_core/ref"
    REQUIRES
        mbedtls
        esp_timer
        drbg
)
