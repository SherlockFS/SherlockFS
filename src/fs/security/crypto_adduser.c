
#include <arpa/inet.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "cryptfs.h"
#include "crypto.h"
#include "hash.h"
#include "print.h"
#include "string.h"
#include "xalloc.h"

ssize_t find_rsa_matching_key(EVP_PKEY *rsa_keypair,
                              struct CryptFS_KeySlot *keys_storage)
{
    BIGNUM *rsa_keypair_modulus = NULL;
    BIGNUM *rsa_keypair_exponent = NULL;

    if (EVP_PKEY_get_bn_param(rsa_keypair, OSSL_PKEY_PARAM_RSA_N,
                              &rsa_keypair_modulus)
        != 1)
        internal_error_exit("Failed to get the private RSA modulus\n",
                            EXIT_FAILURE);

    if (EVP_PKEY_get_bn_param(rsa_keypair, OSSL_PKEY_PARAM_RSA_E,
                              &rsa_keypair_exponent)
        != 1)
        internal_error_exit("Failed to get the private RSA exponent\n",
                            EXIT_FAILURE);
    uint8_t i = 0;
    for (; i < NB_ENCRYPTION_KEYS; i++)
    {
        if (!keys_storage[i].occupied)
            continue;

        // Compare the exponent and the modulus of the both keys
        BIGNUM *key_storage_modulus =
            BN_bin2bn(keys_storage[i].rsa_n, RSA_KEY_SIZE_BYTES, NULL);

        uint32_t exponent_host_endianness = ntohl(keys_storage[i].rsa_e);
        BIGNUM *key_storage_exponent = BN_new();
        if (!BN_set_word(key_storage_exponent, exponent_host_endianness))
            internal_error_exit("Failed to set the public RSA exponent\n",
                                EXIT_FAILURE);

        if (BN_cmp(key_storage_modulus, rsa_keypair_modulus) == 0
            && BN_cmp(key_storage_exponent, rsa_keypair_exponent) == 0)
        {
            BN_free(key_storage_modulus);
            BN_free(key_storage_exponent);
            break;
        }

        BN_free(key_storage_modulus);
        BN_free(key_storage_exponent);
    }
    BN_free(rsa_keypair_modulus);
    BN_free(rsa_keypair_exponent);

    return i == NB_ENCRYPTION_KEYS ? -1 : i;
}
