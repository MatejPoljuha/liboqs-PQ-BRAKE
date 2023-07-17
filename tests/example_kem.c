/*
 * example_kem.c
 *
 * MODIFIED - Minimal example of a Diffie-Hellman-style post-quantum key encapsulation
 * implemented in liboqs, MODIFIED to check the new functionality of using a custom shared message/shared secret.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

/* This function gives an example of the operations performed by both
 * the decapsulator and the encapsulator in a single KEM session,
 * using only compile-time macros and allocating variables
 * statically on the stack, calling a specific algorithm's functions
 * directly.
 *
 * The macros OQS_KEM_kyber_768_length_* and the functions
 * OQS_KEM_kyber_768_* are only defined if the algorithm
 * Kyber-768 was enabled at compile-time which must be
 * checked using the OQS_ENABLE_KEM_kyber_768 macro.
 *
 * <oqs/oqsconfig.h>, which is included in <oqs/oqs.h>, contains macros
 * indicating which algorithms were enabled when this instance of liboqs
 * was compiled.
 * MODIFIED - uses the new CPA-only encap/decap functions
 */
static OQS_STATUS CPA_example_stack(void) {
#ifndef OQS_ENABLE_KEM_kyber_768 // if Kyber-768 was not enabled at compile-time
	printf("[example_stack] OQS_KEM_kyber_768 was not enabled at "
	       "compile-time.\n");
	return OQS_SUCCESS; // nothing done successfully ;-)
#else
	uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
	uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
	uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
	uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

	OQS_STATUS rc_cpa = OQS_KEM_kyber_768_keypair(public_key, secret_key);

	if (rc_cpa != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);

		return OQS_ERROR;
	}

    /* Modified version of above code block to test the new custom shared secret functionality, we just use 0,1,2,...,31 as the input */
    int fill_buf;
    uint8_t custom_shared_secret[2*32];
    for (fill_buf = 0; fill_buf < 32; fill_buf++) {
        custom_shared_secret[fill_buf] = fill_buf;
    }

    printf("\n-----------------------------------------------------------------------------");
    printf("\nCPA-only variant: ");
    printf("\n-----------------------------------------------------------------------------");
    printf("\nENCAPSULATION: ");

    rc_cpa = OQS_KEM_kyber_768_encaps_custom_secret_CPA(custom_shared_secret, ciphertext, shared_secret_e, public_key);
    if (rc_cpa != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);

        return OQS_ERROR;
    }

    printf("\nDECAPSULATION: ");

    rc_cpa = OQS_KEM_kyber_768_decaps_custom_secret_CPA(shared_secret_d, ciphertext, secret_key);
	if (rc_cpa != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);

		return OQS_ERROR;
	}
    printf("\n-----------------------------------------------------------------------------");
	return OQS_SUCCESS; // success!
#endif
}

static OQS_STATUS CCA_example_stack(void) {
#ifndef OQS_ENABLE_KEM_kyber_768 // if Kyber-768 was not enabled at compile-time
    printf("[example_stack] OQS_KEM_kyber_768 was not enabled at "
	       "compile-time.\n");
	return OQS_SUCCESS; // nothing done successfully ;-)
#else
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

    OQS_STATUS rc_cca = OQS_KEM_kyber_768_keypair(public_key, secret_key);

    if (rc_cca != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);

        return OQS_ERROR;
    }

    /* Modified version of above code block to test the new custom shared secret functionality, we just use 0,1,2,...,31 as the input */
    int fill_buf;
    uint8_t custom_shared_secret[2*32];
    for (fill_buf = 0; fill_buf < 32; fill_buf++) {
        custom_shared_secret[fill_buf] = fill_buf;
    }

    printf("\n\n-----------------------------------------------------------------------------");
    printf("\nCCA variant: ");
    printf("\n-----------------------------------------------------------------------------");
    printf("\nENCAPSULATION: ");

    rc_cca = OQS_KEM_kyber_768_encaps_custom_secret_CCA(custom_shared_secret, ciphertext, shared_secret_e, public_key);
    if (rc_cca != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);

        return OQS_ERROR;
    }

    printf("\nDECAPSULATION: ");
    rc_cca = OQS_KEM_kyber_768_decaps_custom_secret_CCA(shared_secret_d, ciphertext, secret_key);
    if (rc_cca != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
        cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);

        return OQS_ERROR;
    }
    printf("\n-----------------------------------------------------------------------------");
    return OQS_SUCCESS; // success!
#endif
}

int main(void) {
	OQS_init();
	if (CPA_example_stack() == OQS_SUCCESS && CCA_example_stack() == OQS_SUCCESS) {
        printf("\nEncapsulation, Decapsulation successful.\n(uncomment the print lines in the underlying encap/decap_CPA/CCA functions to see the values of the input message and output shared secrets.)");
		OQS_destroy();
		return EXIT_SUCCESS;
	} else {
		OQS_destroy();
		return EXIT_FAILURE;
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}
