
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "cryptfs.h"
#include "crypto.h"
#include "print.h"

ssize_t find_rsa_matching_key(EVP_PKEY *rsa_keypair,
                              struct CryptFS_Key *keys_storage)
{
    BIGNUM *rsa_keypair_modulus = NULL;

    if (EVP_PKEY_get_bn_param(rsa_keypair, OSSL_PKEY_PARAM_RSA_N,
                              &rsa_keypair_modulus)
        != 1)
        internal_error_exit("Failed to get the private RSA modulus\n",
                            EXIT_FAILURE);
    uint8_t i = 0;
    for (; i < NB_ENCRYPTION_KEYS; i++)
    {
        // Compare the exponent and the modulus of the both keys
        BIGNUM *key_storage_modulus =
            BN_bin2bn(keys_storage[i].rsa_n, RSA_KEY_SIZE_BYTES, NULL);
        if (BN_cmp(key_storage_modulus, rsa_keypair_modulus) == 0)
        {
            BN_free(key_storage_modulus);
            break;
            // // Init for checking the RSA private parameters
            // EVP_PKEY_CTX *rsa_private_ctx = EVP_PKEY_CTX_new(rsa_keypair,
            // NULL); if (rsa_private_ctx == NULL)
            //     internal_error_exit("Failed to create the EVP_PKEY_CTX\n",
            //                         EXIT_FAILURE);

            // if (EVP_PKEY_pairwise_check(rsa_private_ctx) == 1)
            // {
            //     BN_free(key_storage_modulus);
            //     EVP_PKEY_CTX_free(rsa_private_ctx);
            //     break;
            // }
            // EVP_PKEY_CTX_free(rsa_private_ctx);
        }
        BN_free(key_storage_modulus);
    }
    BN_free(rsa_keypair_modulus);

    return i == NB_ENCRYPTION_KEYS ? -1 : i;
}
