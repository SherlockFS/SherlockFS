#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cryptfs.h"
#include "crypto.h"
#include "passphrase.h"
#include "print.h"
#include "xalloc.h"

unsigned char *generate_aes_key(void)
{
    unsigned char *aes_key = xmalloc(AES_KEY_SIZE_BYTES, 1);

    print_info("Generating AES key...\n");
    if (RAND_bytes(aes_key, AES_KEY_SIZE_BYTES) != 1)
        internal_error_exit("Failed to generate AES key\n", EXIT_FAILURE);

    return aes_key;
}

EVP_PKEY *generate_rsa_keypair(void)
{
    EVP_PKEY *rsa_keypair = EVP_PKEY_new();
    if (!rsa_keypair)
        internal_error_exit("Failed to allocate RSA keypair\n", EXIT_FAILURE);

    print_info("Generating a RSA keypair (for AES key encryption)...\n");
    unsigned int bits = RSA_KEY_SIZE_BITS;
    unsigned int e = RSA_F4;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0)
        internal_error_exit("Failed to initialize RSA keypair generation\n",
                            EXIT_FAILURE);

    params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    params[1] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &e);
    params[2] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0)
        internal_error_exit("Failed to set RSA key parameter\n", EXIT_FAILURE);

    if (EVP_PKEY_generate(pctx, &rsa_keypair) != 1)
        internal_error_exit("Failed to generate RSA keypair\n", EXIT_FAILURE);
    EVP_PKEY_CTX_free(pctx);

    print_success("RSA keypair generated successfully!\n");
    return rsa_keypair;
}

void store_keys_in_keys_storage(struct CryptFS_KeySlot *keys_storage,
                                EVP_PKEY *rsa_keypair, unsigned char *aes_key)
{
    static char zero[RSA_KEY_SIZE_BYTES] = { 0 };

    size_t i = 0;
    while (i < NB_ENCRYPTION_KEYS)
    {
        // Check if keys_storage[i].rsa_n is full of 0
        // and keys_storage[i].rsa_e is 0
        if (memcmp(keys_storage[i].rsa_n, zero, RSA_KEY_SIZE_BYTES) == 0
            && keys_storage[i].rsa_e == 0)
        {
            // Get the RSA modulus
            BIGNUM *modulus_bn = NULL;
            BIGNUM *exponent_bn = NULL;

            // Get N from rsa_keypair as a BIGNUM
            if (EVP_PKEY_get_bn_param(rsa_keypair, OSSL_PKEY_PARAM_RSA_N,
                                      &modulus_bn)
                    != 1 // Get the RSA modulus
                || BN_bn2bin(modulus_bn,
                             (unsigned char *)&keys_storage[i].rsa_n)
                    != RSA_KEY_SIZE_BYTES) // Store the RSA modulus in
                                           // keys_storage[i].rsa_n
                internal_error_exit("Failed to store RSA modulus\n",
                                    EXIT_FAILURE);

            // Get E from rsa_keypair as a uint32_t
            if (EVP_PKEY_get_bn_param(rsa_keypair, OSSL_PKEY_PARAM_RSA_E,
                                      &exponent_bn)
                != 1)
                internal_error_exit("Failed to store RSA exponent\n",
                                    EXIT_FAILURE);
            keys_storage[i].rsa_e = htonl(BN_get_word(exponent_bn));

            // EVP_PKEY_encrypt CTX setup with the RSA keypair
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
            if (pctx == NULL || EVP_PKEY_encrypt_init(pctx) <= 0)
                internal_error_exit("Failed to initialize RSA key encryption\n",
                                    EXIT_FAILURE);

            // Encrypt the AES key with the RSA keypair
            size_t aes_key_encrypted_size = RSA_KEY_SIZE_BYTES;
            size_t aes_key_size = AES_KEY_SIZE_BYTES;
            unsigned char *aes_key_encrypted = rsa_encrypt_data(
                rsa_keypair, aes_key, aes_key_size, &aes_key_encrypted_size);

            if (aes_key_encrypted == NULL)
                internal_error_exit("Failed to encrypt AES key\n",
                                    EXIT_FAILURE);

            // Copy the encrypted AES key in keys_storage[i].aes_key_ciphered
            memcpy(keys_storage[i].aes_key_ciphered, aes_key_encrypted,
                   aes_key_encrypted_size);

            BN_free(modulus_bn);
            EVP_PKEY_CTX_free(pctx);
            BN_free(exponent_bn);
            free(aes_key_encrypted);

            break;
        }
        i++;
    }

    if (i == NB_ENCRYPTION_KEYS)
        error_exit(
            "No more space for any more keys, there is already %lu users "
            "in the keys storage\n",
            EXIT_FAILURE, NB_ENCRYPTION_KEYS);
}

void write_rsa_keys_on_disk(EVP_PKEY *rsa_keypair, const char *public_key_path,
                            const char *private_key_path, char *passphrase)
{
    if (public_key_path)
    {
        print_info("Storing the RSA public key in '%s'...\n", public_key_path);
        FILE *public_key = fopen(public_key_path, "w+");
        if (public_key == NULL)
            internal_error_exit("Failed to open the public key '%s'\n",
                                EXIT_FAILURE, public_key_path);

        if (PEM_write_PUBKEY(public_key, rsa_keypair) != 1
            || fclose(public_key) != 0)
        {
            ERR_print_errors_fp(stderr);
            internal_error_exit("Failed to write the public key '%s'\n",
                                EXIT_FAILURE, public_key_path);
        }
    }

    if (private_key_path)
    {
        print_info("Writing the RSA private key into '%s'...\n",
                   private_key_path);
        FILE *private_key = fopen(private_key_path, "w+");
        if (private_key == NULL)
            internal_error_exit("Failed to open the private key fil\n",
                                EXIT_FAILURE);
        if (PEM_write_PrivateKey(private_key, rsa_keypair,
                                 passphrase != NULL ? EVP_aes_256_cbc() : NULL,
                                 NULL, 0, NULL, passphrase)
                != 1
            || fclose(private_key) != 0)
            internal_error_exit("Failed to write the private key '%s'\n",
                                EXIT_FAILURE, private_key_path);

        if (passphrase)
        {
            if (rsa_private_is_encrypted(private_key_path) == true)
                print_info(
                    "The private key has been encrypted with a passphrase\n");
            else
                internal_error_exit("Failed to encrypt the private key '%s'\n",
                                    EXIT_FAILURE, private_key_path);
        }
    }
}
