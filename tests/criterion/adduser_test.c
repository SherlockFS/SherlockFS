#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "adduser.h"
#include "crypto.h"
#include "format.h"
#include "print.h"
#include "readfs.h"

void cr_redirect_stdall(void)
{
    cr_redirect_stdout();
    cr_redirect_stderr();
}

Test(cfs_adduser, not_existing, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stderr)
{
    cryptfs_adduser("build/tests/cfs_adduser.not_existing.test.cfs",
                    "build/tests/cfs_adduser.not_existing.public.pem",
                    "build/tests/cfs_adduser.not_existing.private.pem");
}

Test(cfs_adduser, not_formated, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stdall)
{
    // Create random file
    FILE *file = fopen("build/tests/cfs_adduser.not_formated.test.cfs", "w");
    if (file == NULL)
    {
        perror("Impossible to create the file");
        exit(EXIT_FAILURE + 1);
    }
    fclose(file);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "build/tests/cfs_adduser.not_formated.public.pem",
        "build/tests/cfs_adduser.not_formated.private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/cfs_adduser.not_formated.other_public.pem",
        NULL, NULL);

    cryptfs_adduser("build/tests/cfs_adduser.not_formated.test.cfs",
                    "build/tests/cfs_adduser.not_formated.public.pem",
                    "build/tests/cfs_adduser.not_formated.private.pem");

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
}

Test(cfs_adduser, formated, .timeout = 10, .init = cr_redirect_stdout)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/cfs_adduser.formated.test.cfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/tests/cfs_adduser.formated.test.cfs",
              "build/tests/cfs_adduser.formated.test.public.pem",
              "build/tests/cfs_adduser.formated.test.private.pem", NULL,
              my_rsa);
    cr_assert(
        is_already_formatted("build/tests/cfs_adduser.formated.test.cfs"));

    // Read CryptFS structure
    struct CryptFS *cfs =
        read_cryptfs_headers("build/tests/cfs_adduser.formated.test.cfs");

    // Check if second key storage buf is empty
    cr_assert_arr_eq(cfs->keys_storage[1].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                     AES_KEY_SIZE_BYTES);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "build/tests/cfs_adduser.formated.my_public.pem",
        "build/tests/cfs_adduser.formated.my_private.pem", NULL);
    write_rsa_keys_on_disk(other_rsa,
                           "build/tests/cfs_adduser.formated.other_public.pem",
                           NULL, NULL);

    cryptfs_adduser("build/tests/cfs_adduser.formated.test.cfs",
                    "build/tests/cfs_adduser.formated.other_public.pem",
                    "build/tests/cfs_adduser.formated.my_private.pem");

    // Read CryptFS structure
    free(cfs);
    cfs = read_cryptfs_headers("build/tests/cfs_adduser.formated.test.cfs");

    // Check if second key storage buf is not empty
    cr_assert_arr_neq(cfs->keys_storage[1].aes_key_ciphered,
                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                      AES_KEY_SIZE_BYTES);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(cfs);
}

Test(cfs_adduser, already_exists, .timeout = 10, .init = cr_redirect_stdall)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/cfs_adduser.already_exists.test.cfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();

    format_fs("build/tests/cfs_adduser.already_exists.test.cfs",
              "build/tests/cfs_adduser.already_exists.test.public.pem",
              "build/tests/cfs_adduser.already_exists.test.private.pem", NULL,
              my_rsa);

    cr_assert(is_already_formatted(
        "build/tests/cfs_adduser.already_exists.test.cfs"));

    // Read CryptFS structure
    struct CryptFS *cfs =
        read_cryptfs_headers("build/tests/cfs_adduser.already_exists.test.cfs");

    // Check if second and third keys storages are empty
    cr_assert_arr_eq(cfs->keys_storage[1].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES * 2]){ 0 },
                     AES_KEY_SIZE_BYTES * 2);

    write_rsa_keys_on_disk(
        my_rsa, "build/tests/cfs_adduser.already_exists.my_public.pem",
        "build/tests/cfs_adduser.already_exists.my_private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/cfs_adduser.already_exists.other_public.pem",
        NULL, NULL);

    int cfs_ret = 0;
    for (u_int8_t i = 0; i < 2; i++) // Add the same user twice
        cfs_ret = cryptfs_adduser(
            "build/tests/cfs_adduser.already_exists.test.cfs",
            "build/tests/cfs_adduser.already_exists.other_public.pem",
            "build/tests/cfs_adduser.already_exists.my_private.pem");

    cr_assert_eq(cfs_ret, -1);

    // Read CryptFS structure
    free(cfs);
    cfs =
        read_cryptfs_headers("build/tests/cfs_adduser.already_exists.test.cfs");

    // Check if second key storage buf is not empty
    cr_assert_arr_neq(cfs->keys_storage[1].aes_key_ciphered,
                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                      AES_KEY_SIZE_BYTES);

    // Check if third key storage buf is empty
    cr_assert_arr_eq(cfs->keys_storage[2].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                     AES_KEY_SIZE_BYTES);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(cfs);
}
