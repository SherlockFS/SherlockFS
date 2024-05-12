#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <errno.h>
#include <openssl/rsa.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "crypto.h"
#include "xalloc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
Test(is_key_valid, valid, .timeout = 10, .init = cr_redirect_stdout)
{
    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    cr_assert_eq(is_key_valid(rsa_keypair), true);
    EVP_PKEY_free(rsa_keypair);
}

Test(is_key_valid, not_is_key_valid_public, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Generate full bullshit BIGNUMs and place them in a RSA keypair
    BIGNUM *rsa_keypair_modulus = BN_new();
    BIGNUM *rsa_keypair_exponent = BN_new();

    BN_rand(rsa_keypair_modulus, RSA_KEY_SIZE_BITS, 0, 0);
    BN_rand(rsa_keypair_exponent, sizeof(uint32_t) * 8, 0, 0);

    EVP_PKEY *rsa_keypair = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_keypair, RSA_new());
    RSA_set0_key(EVP_PKEY_get0_RSA(rsa_keypair), rsa_keypair_modulus, NULL,
                 rsa_keypair_exponent);

    cr_assert_eq(is_key_valid(rsa_keypair), false);

    // Free memory
    BN_free(rsa_keypair_modulus);
    BN_free(rsa_keypair_exponent);
    EVP_PKEY_free(rsa_keypair);
}

Test(is_key_valid, not_is_key_valid_private, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Generate full bullshit BIGNUMs and place them in a RSA keypair
    BIGNUM *rsa_keypair_modulus = BN_new();
    BIGNUM *rsa_keypair_exponent = BN_new();
    BIGNUM *rsa_keypair_d = BN_new();

    BN_rand(rsa_keypair_modulus, RSA_KEY_SIZE_BITS, 0, 0);
    BN_rand(rsa_keypair_exponent, sizeof(uint32_t) * 8, 0, 0);
    BN_rand(rsa_keypair_d, RSA_KEY_SIZE_BITS, 0, 0);

    EVP_PKEY *rsa_keypair = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_keypair, RSA_new());

    cr_assert_eq(is_key_valid(rsa_keypair), false);

    // Free memory
    BN_free(rsa_keypair_modulus);
    EVP_PKEY_free(rsa_keypair);
    BN_free(rsa_keypair_exponent);
    BN_free(rsa_keypair_d);
}

Test(is_key_valid, not_2048_size, .timeout = 10, .init = cr_redirect_stdout)
{
    // Generate a valid RSA keypair, but N is not RSA_KEY_SIZE_BITS bits long
    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    RSA *rsa = RSAPrivateKey_dup(EVP_PKEY_get0_RSA(rsa_keypair));

    // Set the RSA modulus to the invalid modulus
    BIGNUM *rsa_keypair_modulus = BN_new();
    BN_rand(rsa_keypair_modulus, RSA_KEY_SIZE_BITS * 2, 0, 0);
    RSA_set0_key(rsa, rsa_keypair_modulus, NULL, NULL);

    // Convert the RSA keypair to an EVP_PKEY
    EVP_PKEY *rsa_keypair_modified = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_keypair_modified, rsa);

    cr_assert_eq(is_key_valid(rsa_keypair_modified), false);

    // Free memory
    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(rsa_keypair_modified);
}

Test(is_key_valid, not_2048_size_2, .timeout = 10, .init = cr_redirect_stdout)
{
    // Generate a valid RSA keypair, but N is not RSA_KEY_SIZE_BITS bits long
    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    RSA *rsa = RSAPrivateKey_dup(EVP_PKEY_get0_RSA(rsa_keypair));

    // Set the RSA modulus to the invalid modulus
    BIGNUM *rsa_keypair_modulus = BN_new();
    BN_rand(rsa_keypair_modulus, RSA_KEY_SIZE_BITS / 2, 0, 0);
    RSA_set0_key(rsa, rsa_keypair_modulus, NULL, NULL);

    // Convert the RSA keypair to an EVP_PKEY
    EVP_PKEY *rsa_keypair_modified = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_keypair_modified, rsa);

    cr_assert_eq(is_key_valid(rsa_keypair_modified), false);

    // Free memory
    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(rsa_keypair_modified);
}

#pragma GCC diagnostic pop

Test(crypto_disk, load_rsa_keypair_from_disk, .init = cr_redirect_stdout,
     .timeout = 10)
{
    remove("build/tests/crypto_disk__load_rsa_keypair_from_disk");
    int dir_res =
        mkdir("build/tests/crypto_disk__load_rsa_keypair_from_disk", 0755);
    if (dir_res != 0 && errno != EEXIST)
        cr_assert(false, "Impossible to create the directory");

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        rsa_keypair,
        "build/tests/crypto_disk__load_rsa_keypair_from_disk/public.pem",
        "build/tests/crypto_disk__load_rsa_keypair_from_disk/private.pem",
        NULL);
    EVP_PKEY *rsa_keypair_loaded = load_rsa_keypair_from_disk(
        "build/tests/crypto_disk__load_rsa_keypair_from_disk/public.pem",
        "build/tests/crypto_disk__load_rsa_keypair_from_disk/private.pem",
        NULL);
    cr_assert_eq(EVP_PKEY_eq(rsa_keypair, rsa_keypair_loaded), 1);
    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(rsa_keypair_loaded);
}
