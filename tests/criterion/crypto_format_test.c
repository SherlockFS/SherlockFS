#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <unistd.h>

#include "cryptfs.h"
#include "crypto.h"
#include "format.h"
#include "hash.h"
#include "xalloc.h"

Test(generate_keys, generate_keys, .init = cr_redirect_stdout, .timeout = 10)
{
    unsigned char *aes_key_zero = xcalloc(AES_KEY_SIZE_BYTES, 1);
    unsigned char *aes_key = generate_aes_key();
    EVP_PKEY *rsa_keypair = generate_rsa_keypair();

    unsigned char *aes_hash_zero =
        sha256_data(aes_key_zero, AES_KEY_SIZE_BYTES);
    unsigned char *aes_hash = sha256_data(aes_key, AES_KEY_SIZE_BYTES);

    // Get RSA pem
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, rsa_keypair, NULL, NULL, 0, NULL, NULL);
    char *rsa_pem = xcalloc(EVP_PKEY_size(rsa_keypair) + 1, 1);
    BIO_read(bio, rsa_pem, EVP_PKEY_size(rsa_keypair));
    BIO_free_all(bio);

    cr_assert_arr_neq(aes_hash_zero, aes_hash, SHA256_DIGEST_LENGTH);

    // Check if PEM starts with "-----BEGIN PRIVATE KEY-----"
    cr_assert_arr_eq(rsa_pem, "-----BEGIN PRIVATE KEY-----",
                     strlen("-----BEGIN PRIVATE KEY-----"));

    free(aes_key_zero);
    free(aes_key);
    free(aes_hash_zero);
    free(aes_hash);
    EVP_PKEY_free(rsa_keypair);
    free(rsa_pem);
}

Test(store_keys_in_keys_storage, store_keys_in_keys_storage,
     .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS_KeySlot *keys_storage = xaligned_calloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_KeySlot));

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    unsigned char *aes_key = generate_aes_key();

    store_keys_in_keys_storage(keys_storage, rsa_keypair, aes_key);

    // Check if the RSA modulus and the RSA public exponent are stored in the
    // header
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    BIGNUM *n = BN_bin2bn((const unsigned char *)&keys_storage[0].rsa_n,
                          RSA_KEY_SIZE_BYTES, NULL);

    BIGNUM *n_storage = NULL;
    EVP_PKEY_get_bn_param(rsa_keypair, "n", &n_storage);
    cr_assert(BN_cmp(n, n_storage) == 0, "%s != %s\n", BN_bn2hex(n),
              BN_bn2hex(n_storage));

    // Decrypt stored AES key and compares it to the constant aes_key_const
    size_t aes_key_size = 0;
    unsigned char *aes_key_decrypted =
        rsa_decrypt_data(rsa_keypair, keys_storage[0].aes_key_ciphered,
                         RSA_KEY_SIZE_BYTES, &aes_key_size);
    cr_assert_arr_eq(aes_key, aes_key_decrypted, AES_KEY_SIZE_BYTES);
    cr_assert_eq(aes_key_size, AES_KEY_SIZE_BYTES);

    free(aes_key);
    free(aes_key_decrypted);
    free(keys_storage);
    EVP_PKEY_free(rsa_keypair);
    BN_free(e);
    BN_free(n);
    BN_free(n_storage);
}

Test(write_rsa_keys_on_disk, write_rsa_keys_on_disk, .init = cr_redirect_stdout,
     .timeout = 10)
{
    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    unsigned char *aes_key = generate_aes_key();

    write_rsa_keys_on_disk(
        rsa_keypair, "build/tests/write_rsa_keys_on_disk.public.pem",
        "build/tests/write_rsa_keys_on_disk.private.pem", NULL);

    // Check if the files exists
    cr_assert(access("build/tests/write_rsa_keys_on_disk.public.pem", F_OK)
                  == 0,
              "File 'build/write_rsa_keys_on_disk.public.pem' does not exist");
    cr_assert(access("build/tests/write_rsa_keys_on_disk.private.pem", F_OK)
                  == 0,
              "File 'build/write_rsa_keys_on_disk.private.pem' does not exist");

    // Check if these file are correct PEM keys
    FILE *fp = fopen("build/tests/write_rsa_keys_on_disk.public.pem", "r");
    char *rsa_pem = xcalloc(EVP_PKEY_size(rsa_keypair) + 1, 1);
    fread(rsa_pem, 1, EVP_PKEY_size(rsa_keypair), fp);
    fclose(fp);
    cr_assert_arr_eq(rsa_pem, "-----BEGIN PUBLIC KEY-----",
                     strlen("-----BEGIN PUBLIC KEY-----"));
    free(rsa_pem);

    fp = fopen("build/tests/write_rsa_keys_on_disk.private.pem", "r");
    rsa_pem = xcalloc(EVP_PKEY_size(rsa_keypair) + 1, 1);
    fread(rsa_pem, 1, EVP_PKEY_size(rsa_keypair), fp);
    fclose(fp);
    cr_assert_arr_eq(rsa_pem, "-----BEGIN PRIVATE KEY-----",
                     strlen("-----BEGIN PRIVATE KEY-----"));
    free(rsa_pem);

    free(aes_key);
    EVP_PKEY_free(rsa_keypair);

    // Remove the files
    remove("build/tests/write_rsa_keys_on_disk.public.pem");
    remove("build/tests/write_rsa_keys_on_disk.private.pem");
}

Test(find_rsa_matching_key, no_key, .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS_KeySlot *keys_storage =
        xcalloc(1, sizeof(struct CryptFS_KeySlot));

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    EVP_PKEY *rsa_keypair_different = generate_rsa_keypair();

    unsigned char *aes_key = generate_aes_key();

    store_keys_in_keys_storage(keys_storage, rsa_keypair, aes_key);

    cr_assert_eq(find_rsa_matching_key(rsa_keypair_different, keys_storage),
                 -1);

    free(aes_key);
    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(rsa_keypair_different);
    free(keys_storage);
}

Test(find_rsa_matching_key, key, .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS_KeySlot *keys_storage = xaligned_calloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_KeySlot));

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();

    unsigned char *aes_key = generate_aes_key();

    store_keys_in_keys_storage(keys_storage, rsa_keypair, aes_key);

    cr_assert_eq(find_rsa_matching_key(rsa_keypair, keys_storage), 0);

    free(keys_storage);
    free(aes_key);
    EVP_PKEY_free(rsa_keypair);
}
