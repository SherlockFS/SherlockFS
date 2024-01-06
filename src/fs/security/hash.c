#include "hash.h"

#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "cryptfs.h"
#include "print.h"
#include "xalloc.h"

unsigned char *sha256_data(void *data, size_t len_data)
{
    unsigned char *hash = xmalloc(SHA256_DIGEST_LENGTH, 1);

    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();
    if (!sha256_ctx)
        internal_error_exit("Failed to allocate SHA256 context\n",
                            EXIT_FAILURE);

    if (EVP_DigestInit(sha256_ctx, EVP_sha256()) != 1
        || EVP_DigestUpdate(sha256_ctx, data, len_data) != 1
        || EVP_DigestFinal(sha256_ctx, hash, NULL) != 1)
        internal_error_exit("Failed to compute SHA256 hash\n", errno);

    EVP_MD_CTX_free(sha256_ctx);
    return hash;
}

unsigned char *hash_rsa_public_key(EVP_PKEY *rsa_public)
{
    BIGNUM *rsa_n_bn = NULL;
    BIGNUM *rsa_e_bn = NULL;

    if (EVP_PKEY_get_bn_param(rsa_public, OSSL_PKEY_PARAM_RSA_N, &rsa_n_bn) != 1
        || EVP_PKEY_get_bn_param(rsa_public, OSSL_PKEY_PARAM_RSA_E, &rsa_e_bn)
            != 1)
        internal_error_exit(
            "Failed to get the private RSA modulus or exponent\n",
            EXIT_FAILURE);

    // Getting BIGNUMs sizes
    int rsa_n_size = BN_num_bytes(rsa_n_bn);
    int rsa_e_size = BN_num_bytes(rsa_e_bn);

    if (rsa_n_size <= 0 || rsa_e_size <= 0)
        internal_error_exit("Failed to get the RSA modulus or exponent size\n",
                            EXIT_FAILURE);

    // Allocating hash input buffer
    unsigned rsa_n_e_buf_size = rsa_n_size + rsa_e_size;
    unsigned char *rsa_n_e_buf = xmalloc(rsa_n_e_buf_size, sizeof(char));

    // Convert BIGNUMs to buffer
    if (BN_bn2bin(rsa_n_bn, rsa_n_e_buf) != rsa_n_size)
        internal_error_exit("rsa_n_bn not correctly copied to rsa_n_e_buf",
                            EXIT_FAILURE);
    if (BN_bn2bin(rsa_e_bn, rsa_n_e_buf + rsa_n_size) != rsa_e_size)
        internal_error_exit("rsa_e_bn not correctly copied to rsa_n_e_buf",
                            EXIT_FAILURE);
    BN_free(rsa_n_bn);
    BN_free(rsa_e_bn);

    uint8_t *rsa_n_e_hash = sha256_data(rsa_n_e_buf, rsa_n_e_buf_size);
    free(rsa_n_e_buf);

    return rsa_n_e_hash;
}
