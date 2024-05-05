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

Test(shlkfs_adduser, not_existing, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stderr)
{
    // Execute command (not exiting function)
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_adduser.not_existing.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    cryptfs_adduser("build/tests/shlkfs_adduser.not_existing.test.shlkfs",
                    "build/tests/shlkfs_adduser.not_existing.public.pem",
                    "build/tests/shlkfs_adduser.not_existing.private.pem");
}

Test(shlkfs_adduser, not_formated, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_adduser.not_formated.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "build/tests/shlkfs_adduser.not_formated.public.pem",
        "build/tests/shlkfs_adduser.not_formated.private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/shlkfs_adduser.not_formated.other_public.pem",
        NULL, NULL);

    cryptfs_adduser("build/tests/shlkfs_adduser.not_formated.test.shlkfs",
                    "build/tests/shlkfs_adduser.not_formated.public.pem",
                    "build/tests/shlkfs_adduser.not_formated.private.pem");

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
}

Test(shlkfs_adduser, formated, .timeout = 10, .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero of=build/tests/shlkfs_adduser.formated.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/shlkfs_adduser.formated.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/tests/shlkfs_adduser.formated.test.shlkfs",
              "build/tests/shlkfs_adduser.formated.test.public.pem",
              "build/tests/shlkfs_adduser.formated.test.private.pem", "label",
              NULL, my_rsa);
    cr_assert(is_already_formatted(
        "build/tests/shlkfs_adduser.formated.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs =
        read_cryptfs_headers("build/tests/shlkfs_adduser.formated.test.shlkfs");

    // Check if second key storage buf is empty
    cr_assert_arr_eq(shlkfs->keys_storage[1].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                     AES_KEY_SIZE_BYTES);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "build/tests/shlkfs_adduser.formated.my_public.pem",
        "build/tests/shlkfs_adduser.formated.my_private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/shlkfs_adduser.formated.other_public.pem", NULL,
        NULL);

    cryptfs_adduser("build/tests/shlkfs_adduser.formated.test.shlkfs",
                    "build/tests/shlkfs_adduser.formated.other_public.pem",
                    "build/tests/shlkfs_adduser.formated.my_private.pem");

    // Read CryptFS structure
    free(shlkfs);
    shlkfs =
        read_cryptfs_headers("build/tests/shlkfs_adduser.formated.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_arr_neq(shlkfs->keys_storage[1].aes_key_ciphered,
                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                      AES_KEY_SIZE_BYTES);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);
}

Test(shlkfs_adduser, already_exists, .timeout = 10, .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_adduser.already_exists.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/shlkfs_adduser.already_exists.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();

    format_fs("build/tests/shlkfs_adduser.already_exists.test.shlkfs",
              "build/tests/shlkfs_adduser.already_exists.test.public.pem",
              "build/tests/shlkfs_adduser.already_exists.test.private.pem",
              "label", NULL, my_rsa);

    cr_assert(is_already_formatted(
        "build/tests/shlkfs_adduser.already_exists.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_adduser.already_exists.test.shlkfs");

    // Check if second and third keys storages are empty
    cr_assert_arr_eq(shlkfs->keys_storage[1].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES * 2]){ 0 },
                     AES_KEY_SIZE_BYTES * 2);

    write_rsa_keys_on_disk(
        my_rsa, "build/tests/shlkfs_adduser.already_exists.my_public.pem",
        "build/tests/shlkfs_adduser.already_exists.my_private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/shlkfs_adduser.already_exists.other_public.pem",
        NULL, NULL);

    int shlkfs_ret = 0;
    for (u_int8_t i = 0; i < 2; i++) // Add the same user twice
        shlkfs_ret = cryptfs_adduser(
            "build/tests/shlkfs_adduser.already_exists.test.shlkfs",
            "build/tests/shlkfs_adduser.already_exists.other_public.pem",
            "build/tests/shlkfs_adduser.already_exists.my_private.pem");

    cr_assert_eq(shlkfs_ret, -1);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_adduser.already_exists.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_arr_neq(shlkfs->keys_storage[1].aes_key_ciphered,
                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                      AES_KEY_SIZE_BYTES);

    // Check if third key storage buf is empty
    cr_assert_arr_eq(shlkfs->keys_storage[2].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                     AES_KEY_SIZE_BYTES);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);
}
