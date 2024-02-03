#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypto.h"
#include "passphrase.h"
#include "print.h"
#include "xalloc.h"

bool is_key_valid(EVP_PKEY *rsa_key)
{
    bool err = true;

    // 1: Check if RSA key is not NULL
    err &= rsa_key != NULL;
    if (!err)
        return err;

    // 2: Check if RSA key is RSA
    err &= EVP_PKEY_id(rsa_key) == EVP_PKEY_RSA;
    if (!err)
        return err;

    // 3: Check if RSA key is valid
    EVP_PKEY_CTX *rsa_private_ctx = EVP_PKEY_CTX_new(rsa_key, NULL);

    err &= rsa_private_ctx != NULL;
    if (!err)
        return err;

    size_t raw_private_key_len = 0;
    EVP_PKEY_get_raw_private_key(rsa_key, NULL, &raw_private_key_len);

    if (raw_private_key_len != 0)
        err &= EVP_PKEY_private_check(rsa_private_ctx) == 1;
    err &= EVP_PKEY_public_check(rsa_private_ctx) == 1;
    EVP_PKEY_CTX_free(rsa_private_ctx);
    if (!err)
        return err;

    // 4: Check if N is RSA_KEY_SIZE_BYTES bits long
    err &= EVP_PKEY_get_size(rsa_key) == RSA_KEY_SIZE_BYTES;
    if (!err)
        return err;

    return err;
}

EVP_PKEY *load_rsa_keypair_from_disk(const char *public_key_path,
                                     const char *private_key_path,
                                     char *passphrase)
{
    EVP_PKEY *rsa_keypair = NULL;

    FILE *public_key_file = fopen(public_key_path, "r");
    FILE *private_key_file = fopen(private_key_path, "r");

    if (public_key_file)
    {
        if (PEM_read_PUBKEY(public_key_file, &rsa_keypair, NULL, NULL) == NULL)
            return NULL;
        fclose(public_key_file);
    }

    if (private_key_file)
    {
        if (PEM_read_PrivateKey(private_key_file, &rsa_keypair, NULL,
                                passphrase)
            == NULL)
            return NULL;
        fclose(private_key_file);
    }

    if (is_key_valid(rsa_keypair))
        return rsa_keypair;
    else
    {
        error_exit("Non-compliant or invalid RSA keypair\n", EXIT_FAILURE);
        return NULL;
    }
}

void get_rsa_keys_home_paths(char **public_key_path, char **private_key_path)
{
    char *home = getenv("HOME");
    if (!home)
        internal_error_exit("'HOME' envariable is not defined but required. \n",
                            EXIT_FAILURE);

    if (public_key_path)
    {
        *public_key_path = xcalloc(PATH_MAX + 1, sizeof(char));
        snprintf(*public_key_path, PATH_MAX, "%s/%s", home,
                 ".sherlockfs/public.pem");
    }
    if (private_key_path)
    {
        *private_key_path = xcalloc(PATH_MAX + 1, sizeof(char));
        snprintf(*private_key_path, PATH_MAX, "%s/%s", home,
                 ".sherlockfs/private.pem");
    }
}

EVP_PKEY *load_rsa_keypair_from_home(char **passphrase)
{
    char *public_path = NULL;
    char *private_path = NULL;

    get_rsa_keys_home_paths(&public_path, &private_path);

    EVP_PKEY *rsa_keypair =
        load_rsa_keypair_from_disk(public_path, private_path, *passphrase);

    if (rsa_keypair == NULL)
        error_exit("Impossible to load the RSA keypair\n", EXIT_FAILURE);

    free(private_path);
    free(public_path);

    return rsa_keypair;
}
