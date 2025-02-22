#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  indcpa_keypair(pk, sk);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        MODIFIED - crypto_kem_keypair - based on input
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   
*              - uint8_t *key_input: pointer to input data
*              - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_based_on_input(uint8_t *key_input,
                                      uint8_t *pk,
                                      uint8_t *sk)
{
    indcpa_keypair_based_on_input(key_input, pk, sk);
    memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    // randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
    uint8_t hash_of_y_x[2*KYBER_SYMBYTES];
    int counter;
    for (counter = 0; counter < 32; counter++) {
        hash_of_y_x[counter]=key_input[counter];
    }
    memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,hash_of_y_x,KYBER_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_custom_secret_CPA
*
* Description: MODIFIED - Generates cipher text and shared
*              secret for given public key and input message
*
* Arguments:   - uint8_t *m: pointer to input message
*                (of length KYBER_INDCPA_MSGBYTES bytes)
*              - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_custom_secret_CPA(const uint8_t *input_message,
                                     uint8_t *ct,
                                     uint8_t *ss,
                                     const uint8_t *pk)
{
    uint8_t buf[2*KYBER_SYMBYTES];  // this buf (buffer) variable is what holds the data that gets encapsulated (the message)

    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];

    /* we replace the random data with our desired input,
     * which needs to precisely match the 2*KYBER_SYMBYTES format of the buffer;
     * */
    int fill_buf;
    for (fill_buf = 0; fill_buf < 32; fill_buf++) {
        buf[fill_buf]=input_message[fill_buf];
    }

    /*
    printf("\nOriginal input message: ");
    int counter; // <-----------
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", buf[counter]);
    }
    */

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

    memcpy(ss,buf,2*KYBER_SYMBYTES);    // just because the original function stores the result in ss

    /*
    printf("\nCPA shared secret: ");
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", ss[counter]);
    }
    */
    return 0;
}

/*************************************************
* Name:        crypto_kem_enc_custom_secret_CCA
*
* Description: MODIFIED - Generates cipher text and shared
*              secret for given public key and input message
*
* Arguments:   - uint8_t *m: pointer to input message
*                (of length KYBER_INDCPA_MSGBYTES bytes)
*              - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_custom_secret_CCA(const uint8_t *input_message,
                                     uint8_t *ct,
                                     uint8_t *ss,
                                     const uint8_t *pk)
{
    uint8_t buf[2*KYBER_SYMBYTES];  // this buf (buffer) variable is what holds the data that gets encapsulated (the message)

    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];

    /* we replace the random data with our desired input,
     * which needs to precisely match the 2*KYBER_SYMBYTES format of the buffer;
     * */
    int fill_buf;
    for (fill_buf = 0; fill_buf < 32; fill_buf++) {
        buf[fill_buf]=input_message[fill_buf];
    }

    /*
    printf("\nOriginal input message: ");
    int counter; // <-----------
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", buf[counter]);
    }
    */

    /* Don't release system RNG output */
    hash_h(buf, buf, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2*KYBER_SYMBYTES);

    /*
    printf("\nHashed input message: ");
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", buf[counter]);
    }

    printf("\nCCA shared secret (after KDF): ");
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", ss[counter]);
    }
    */
    return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
    int fail;
    uint8_t buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];
    ALIGNED_UINT8(KYBER_CIPHERTEXTBYTES) cmp;
    const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
    hash_g(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp.coeffs, buf, pk, kr+KYBER_SYMBYTES);

    fail = verify(ct, cmp.coeffs, KYBER_CIPHERTEXTBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2*KYBER_SYMBYTES);

    return 0;
}

/*************************************************
* Name:        MODIFIED - crypto_kem_dec_CPA
*
* Description: Generates shared secret for given
*              cipher text and private key, modified.
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec_custom_secret_CPA(uint8_t *ss,
                                     const uint8_t *ct,
                                     const uint8_t *sk)
{
  uint8_t buf[2*KYBER_SYMBYTES];

  indcpa_dec(buf, ct, sk);

  memcpy(ss,buf,2*KYBER_SYMBYTES);

  /*
  int counter;
  printf("\nCPA decrypted message: ");
  for(counter=0; counter <32; counter++)
  {
      printf("%u ", ss[counter]);
  }
  */

  return 0;
}

/*************************************************
* Name:        MODIFIED - crypto_kem_dec_CCA
*
* Description: Generates shared secret for given
*              cipher text and private key, modified.
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec_custom_secret_CCA(uint8_t *ss,
                                     const uint8_t *ct,
                                     const uint8_t *sk)
{
    int fail;
    uint8_t buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];
    ALIGNED_UINT8(KYBER_CIPHERTEXTBYTES) cmp;
    const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    /*
    int counter;
    printf("\nCPA decrypted (hashed) message: ");
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", buf[counter]);
    }
    */

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
    hash_g(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp.coeffs, buf, pk, kr+KYBER_SYMBYTES);

    fail = verify(ct, cmp.coeffs, KYBER_CIPHERTEXTBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2*KYBER_SYMBYTES);

    /*
    printf("\nCCA decrypted message: ");
    for(counter=0; counter <32; counter++)
    {
        printf("%u ", ss[counter]);
    }
    */
    return 0;
}