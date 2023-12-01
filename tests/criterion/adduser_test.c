#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "adduser.h"
#include "crypto.h"
#include "format.h"
#include "print.h"
#include "readfs.h"

Test(cfs_adduser, not_existing, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stderr)
{
    cryptfs_adduser("build/cfs_adduser.not_existing.test.cfs",
                    "build/cfs_adduser.not_existing.public.pem",
                    "build/cfs_adduser.not_existing.private.pem");
}

void post_not_formated(void)
{
    // Delete created files
    remove("build/cfs_adduser.not_formated.test.cfs");
    remove("build/cfs_adduser.not_formated.public.pem");
    remove("build/cfs_adduser.not_formated.private.pem");
    remove("build/cfs_adduser.not_formated.other_public.pem");
}
Test(cfs_adduser, not_formated, .fini = post_not_formated,
     .exit_code = EXIT_FAILURE, .timeout = 10, .init = cr_redirect_stdout)
{
    // Create random file
    FILE *file = fopen("build/cfs_adduser.not_formated.test.cfs", "w");
    if (file == NULL)
    {
        perror("Impossible to create the file");
        exit(EXIT_FAILURE + 1);
    }
    fclose(file);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(my_rsa, "build/cfs_adduser.not_formated.public.pem",
                           "build/cfs_adduser.not_formated.private.pem", NULL);
    write_rsa_keys_on_disk(other_rsa,
                           "build/cfs_adduser.not_formated.other_public.pem",
                           NULL, NULL);

    cryptfs_adduser("build/cfs_adduser.not_formated.test.cfs",
                    "build/cfs_adduser.not_formated.public.pem",
                    "build/cfs_adduser.not_formated.private.pem");
}

void post_formated(void)
{
    // Delete created files
    remove("build/cfs_adduser.formated.test.cfs");
    remove("build/cfs_adduser.formated.my_public.pem");
    remove("build/cfs_adduser.formated.my_private.pem");
    remove("build/cfs_adduser.formated.other_public.pem");
}
Test(cfs_adduser, formated, .fini = post_formated, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/cfs_adduser.formated.test.cfs");
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/cfs_adduser.formated.test.cfs", NULL, my_rsa);
    cr_assert(is_already_formatted("build/cfs_adduser.formated.test.cfs"));

    // Read CryptFS structure
    struct CryptFS *cfs =
        read_cryptfs_headers("build/cfs_adduser.formated.test.cfs");

    // Check if second key storage buf is empty
    cr_assert_arr_eq(cfs->keys_storage[1].aes_key_ciphered,
                     (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                     AES_KEY_SIZE_BYTES);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(my_rsa, "build/cfs_adduser.formated.my_public.pem",
                           "build/cfs_adduser.formated.my_private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/cfs_adduser.formated.other_public.pem", NULL, NULL);

    cryptfs_adduser("build/cfs_adduser.formated.test.cfs",
                    "build/cfs_adduser.formated.other_public.pem",
                    "build/cfs_adduser.formated.my_private.pem");

    // Read CryptFS structure
    cfs = read_cryptfs_headers("build/cfs_adduser.formated.test.cfs");

    // Check if second key storage buf is not empty
    cr_assert_arr_neq(cfs->keys_storage[1].aes_key_ciphered,
                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
                      AES_KEY_SIZE_BYTES);
}

// void post_already_exists(void)
// {
//     // Delete created files
//     remove("build/cfs_adduser.formated.test.cfs");
//     remove("build/cfs_adduser.formated.my_public.pem");
//     remove("build/cfs_adduser.formated.my_private.pem");
//     remove("build/cfs_adduser.formated.other_public.pem");
// }
// Test(cfs_adduser, already_exists, .fini = post_already_exists, .timeout = 10,
//      .init = cr_redirect_stdout)
// {
//     // Set the device (global variable) to the file (used by
//     read/write_blocks)
//     set_device_path("build/cfs_adduser.already_exists.test.cfs");
//     set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

//     format_fs("build/cfs_adduser.already_exists.test.cfs", NULL, NULL);
//     cr_assert(
//         is_already_formatted("build/cfs_adduser.already_exists.test.cfs"));

//     // Read CryptFS structure
//     struct CryptFS *cfs =
//         read_cryptfs_headers("build/cfs_adduser.already_exists.test.cfs");

//     // Check if second and third keys storages are empty
//     cr_assert_arr_eq(cfs->keys_storage[1].aes_key_ciphered,
//                      (unsigned char[AES_KEY_SIZE_BYTES * 2]){ 0 },
//                      AES_KEY_SIZE_BYTES * 2);

//     // OpenSSL generate keypair and write it to a file
//     EVP_PKEY *my_rsa = generate_rsa_keypair();
//     EVP_PKEY *other_rsa = generate_rsa_keypair();
//     write_rsa_keys_on_disk(
//         my_rsa, "build/cfs_adduser.already_exists.my_public.pem",
//         "build/cfs_adduser.already_exists.my_private.pem", NULL);
//     write_rsa_keys_on_disk(other_rsa,
//                            "build/cfs_adduser.already_exists.other_public.pem",
//                            NULL, NULL);

//     for (u_int8_t i = 0; i < 2; i++)
//     {
//         cryptfs_adduser("build/cfs_adduser.already_exists.test.cfs",
//                         "build/cfs_adduser.already_exists.other_public.pem",
//                         "build/cfs_adduser.already_exists.my_private.pem");
//     }

//     // Read CryptFS structure
//     cfs = read_cryptfs_headers("build/cfs_adduser.already_exists.test.cfs");

//     // Check if second key storage buf is not empty
//     cr_assert_arr_neq(cfs->keys_storage[1].aes_key_ciphered,
//                       (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
//                       AES_KEY_SIZE_BYTES);

//     // Check if third key storage buf is empty
//     cr_assert_arr_eq(cfs->keys_storage[2].aes_key_ciphered,
//                      (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
//                      AES_KEY_SIZE_BYTES);
// }
