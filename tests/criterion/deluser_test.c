#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "adduser.h"
#include "crypto.h"
#include "deluser.h"
#include "format.h"
#include "print.h"
#include "readfs.h"

void cr_redirect_stdall(void);

Test(shlkfs_deluser, not_existing, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stderr)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_deluser.not_existing.test.shlkfs bs=4096 "
           "count=1000 > /dev/null");
    cryptfs_deluser("build/tests/shlkfs_deluser.not_existing.test.shlkfs",
                    "build/tests/shlkfs_deluser.not_existing.private.pem",
                    "build/tests/shlkfs_deluser.not_existing.public.pem");
}

Test(shlkfs_deluser, not_formated, .exit_code = EXIT_FAILURE, .timeout = 10,
     .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_deluser.not_formated.test.shlkfs bs=4096 "
           "count=1000 > /dev/null");

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "build/tests/shlkfs_deluser.not_formated.public.pem",
        "build/tests/shlkfs_deluser.not_formated.private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/shlkfs_deluser.not_formated.other_public.pem",
        NULL, NULL);

    cryptfs_deluser("build/tests/shlkfs_deluser.not_formated.test.shlkfs",
                    "build/tests/shlkfs_deluser.not_formated.private.pem",
                    "build/tests/shlkfs_deluser.not_formated.public.pem");

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
}

Test(shlkfs_deluser, one_user, .timeout = 10, .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero of=build/tests/shlkfs_deluser.one_user.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/shlkfs_deluser.one_user.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/tests/shlkfs_deluser.one_user.test.shlkfs",
              "build/tests/shlkfs_deluser.one_user.test.public.pem",
              "build/tests/shlkfs_deluser.one_user.test.private.pem", "label",
              NULL, my_rsa);
    cr_assert(is_already_formatted(
        "build/tests/shlkfs_deluser.one_user.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs =
        read_cryptfs_headers("build/tests/shlkfs_deluser.one_user.test.shlkfs");

    // Check if second key storage buf is empty
    cr_assert_eq(shlkfs->keys_storage[0].occupied, 1);

    // // OpenSSL generate keypair and write it to a file
    // EVP_PKEY *other_rsa = generate_rsa_keypair();
    // write_rsa_keys_on_disk(
    //     my_rsa, "build/tests/shlkfs_deluser.one_user.my_public.pem",
    //     "build/tests/shlkfs_deluser.one_user.my_private.pem","label", NULL);
    // write_rsa_keys_on_disk(
    //     other_rsa, "build/tests/shlkfs_deluser.one_user.other_public.pem",
    //     NULL, NULL);

    cr_assert_eq(
        cryptfs_deluser("build/tests/shlkfs_deluser.one_user.test.shlkfs",
                        "build/tests/shlkfs_deluser.one_user.test.private.pem",
                        "build/tests/shlkfs_deluser.one_user.test.public.pem"),
        -1);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs =
        read_cryptfs_headers("build/tests/shlkfs_deluser.one_user.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_eq(shlkfs->keys_storage[0].occupied, 1);

    // Free memory
    EVP_PKEY_free(my_rsa);
    // EVP_PKEY_free(other_rsa);
    free(shlkfs);
}

Test(shlkfs_deluser, two_users_delete_other, .timeout = 10,
     .init = cr_redirect_stdall)
{
    system(
        "dd if=/dev/zero of=build/tests/shlkfs_deluser.two_users.test.shlkfs "
        "bs=4096 count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/shlkfs_deluser.two_users.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/tests/shlkfs_deluser.two_users.test.shlkfs",
              "build/tests/shlkfs_deluser.two_users.test.public.pem",
              "build/tests/shlkfs_deluser.two_users.test.private.pem", "label",
              NULL, my_rsa);
    cr_assert(is_already_formatted(
        "build/tests/shlkfs_deluser.two_users.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users.test.shlkfs");

    // Check if second key storage buf is empty
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 0);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/shlkfs_deluser.two_users.other_public.pem",
        NULL, NULL);

    // Add user
    cr_assert_eq(cryptfs_adduser(
                     "build/tests/shlkfs_deluser.two_users.test.shlkfs",
                     "build/tests/shlkfs_deluser.two_users.other_public.pem",
                     "build/tests/shlkfs_deluser.two_users.test.private.pem"),
                 0);

    // Delete the other user
    cr_assert_eq(cryptfs_deluser(
                     "build/tests/shlkfs_deluser.two_users.test.shlkfs",
                     "build/tests/shlkfs_deluser.two_users.test.private.pem",
                     "build/tests/shlkfs_deluser.two_users.other_public.pem"),
                 0);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_eq(shlkfs->keys_storage[0].occupied, 1);
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 0);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);
}

Test(shlkfs_deluser, two_users_delete_me_yes, .timeout = 10,
     .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path(
        "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs",
              "build/tests/shlkfs_deluser.two_users_delete_me.test.public.pem",
              "build/tests/shlkfs_deluser.two_users_delete_me.test.private.pem",
              "label", NULL, my_rsa);
    cr_assert(is_already_formatted(
        "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs");

    // Check if second key storage buf is empty
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 0);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        other_rsa,
        "build/tests/shlkfs_deluser.two_users_delete_me.other_public.pem", NULL,
        NULL);

    // Add user
    cr_assert_eq(
        cryptfs_adduser(
            "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs",
            "build/tests/shlkfs_deluser.two_users_delete_me.other_public.pem",
            "build/tests/shlkfs_deluser.two_users_delete_me.test.private.pem"),
        0);

    // Add "y\n" to stdin
    cr_redirect_stdin();
    FILE *file = cr_get_redirected_stdin();
    fprintf(file, "y\n");
    fflush(file);

    // Delete the my user
    cr_assert_eq(
        cryptfs_deluser(
            "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs",
            "build/tests/shlkfs_deluser.two_users_delete_me.test.private.pem",
            "build/tests/shlkfs_deluser.two_users_delete_me.test.public.pem"),
        0);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users_delete_me.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_eq(shlkfs->keys_storage[0].occupied, 0);
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 1);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);
}

Test(shlkfs_deluser, two_users_delete_me_no, .timeout = 10,
     .init = cr_redirect_stdall)
{
    system("dd if=/dev/zero "
           "of=build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path(
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs(
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs",
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.public.pem",
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.private.pem",
        "label", NULL, my_rsa);
    cr_assert(is_already_formatted(
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs");

    // Check if second key storage buf is empty
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 0);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        other_rsa,
        "build/tests/shlkfs_deluser.two_users_delete_me_no.other_public.pem",
        NULL, NULL);

    // Add user
    cr_assert_eq(
        cryptfs_adduser(
            "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs",
            "build/tests/"
            "shlkfs_deluser.two_users_delete_me_no.other_public.pem",
            "build/tests/"
            "shlkfs_deluser.two_users_delete_me_no.test.private.pem"),
        0);

    // Add "n\n" to stdin
    cr_redirect_stdin();
    FILE *file = cr_get_redirected_stdin();
    fprintf(file, "n\n");
    fflush(file);

    // Delete the my user
    cr_assert_eq(
        cryptfs_deluser(
            "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs",
            "build/tests/"
            "shlkfs_deluser.two_users_delete_me_no.test.private.pem",
            "build/tests/"
            "shlkfs_deluser.two_users_delete_me_no.test.public.pem"),
        -1);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers(
        "build/tests/shlkfs_deluser.two_users_delete_me_no.test.shlkfs");

    // Check if second key storage buf is not empty
    cr_assert_eq(shlkfs->keys_storage[0].occupied, 1);
    cr_assert_eq(shlkfs->keys_storage[1].occupied, 1);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);
}
