// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_kyber.h>

#if defined(OQS_ENABLE_KEM_kyber_768)

OQS_KEM *OQS_KEM_kyber_768_new(void) {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_kyber_768;
	kem->alg_version = "https://github.com/pq-crystals/kyber/commit/28413dfbf523fdde181246451c2bd77199c0f7ff";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_kyber_768_length_public_key;
	kem->length_secret_key = OQS_KEM_kyber_768_length_secret_key;
	kem->length_ciphertext = OQS_KEM_kyber_768_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_kyber_768_length_shared_secret;

	kem->keypair = OQS_KEM_kyber_768_keypair;
	kem->keypair_based_on_input = OQS_KEM_kyber_768_keypair_based_on_input;
	kem->encaps = OQS_KEM_kyber_768_encaps;
    kem->encaps_custom_secret_CCA = OQS_KEM_kyber_768_encaps_custom_secret_CCA;
    kem->encaps_custom_secret_CPA = OQS_KEM_kyber_768_encaps_custom_secret_CPA;
	kem->decaps = OQS_KEM_kyber_768_decaps;
    kem->decaps_custom_secret_CCA = OQS_KEM_kyber_768_decaps_custom_secret_CCA;
    kem->decaps_custom_secret_CPA = OQS_KEM_kyber_768_decaps_custom_secret_CPA;

	return kem;
}

extern int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
extern int pqcrystals_kyber768_avx2_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_kyber768_avx2_keypair_based_on_input(uint8_t *key_input, uint8_t *public_key, uint8_t *secret_key);
extern int pqcrystals_kyber768_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber768_avx2_enc_custom_secret_CCA(const uint8_t *input_message, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber768_avx2_enc_custom_secret_CPA(const uint8_t *input_message, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqcrystals_kyber768_avx2_dec_custom_secret_CCA(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqcrystals_kyber768_avx2_dec_custom_secret_CPA(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#if defined(OQS_ENABLE_KEM_kyber_768_aarch64)
extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

OQS_API OQS_STATUS OQS_KEM_kyber_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) pqcrystals_kyber768_avx2_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_keypair_based_on_input(uint8_t *key_input, uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
        return (OQS_STATUS) pqcrystals_kyber768_avx2_keypair_based_on_input(key_input, public_key, secret_key);
#if defined(OQS_DIST_BUILD)
    } else {
        return (OQS_STATUS) pqcrystals_kyber768_ref_keypair(public_key, secret_key);
    }
#endif /* OQS_DIST_BUILD */
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) pqcrystals_kyber768_avx2_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_encaps_custom_secret_CPA(const uint8_t *input_message, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
        return (OQS_STATUS) pqcrystals_kyber768_avx2_enc_custom_secret_CPA(input_message, ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
    } else {
        return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
    }
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
    #if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_encaps_custom_secret_CCA(const uint8_t *input_message, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
        return (OQS_STATUS) pqcrystals_kyber768_avx2_enc_custom_secret_CCA(input_message, ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
    } else {
        return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
    }
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
    #if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) pqcrystals_kyber768_avx2_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_decaps_custom_secret_CPA(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
        return (OQS_STATUS) pqcrystals_kyber768_avx2_dec_custom_secret_CPA(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
    } else {
        return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
    }
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
    #if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_kyber_768_decaps_custom_secret_CCA(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_kyber_768_avx2)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
        return (OQS_STATUS) pqcrystals_kyber768_avx2_dec_custom_secret_CCA(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
    } else {
        return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
    }
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_kyber_768_aarch64)
    #if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_KYBER768_AARCH64_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
#endif
}

#endif
