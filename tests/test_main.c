#include <assert.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "adduser.h"
#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

int main(void)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("tests/shlkfs_adduser.formated.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("tests/shlkfs_adduser.formated.test.shlkfs",
              "tests/shlkfs_adduser.formated.test.public.pem",
              "tests/shlkfs_adduser.formated.test.private.pem", NULL, my_rsa);
    printf("is_already_formatted: %d\n",
           is_already_formatted("tests/shlkfs_adduser.formated.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs =
        read_cryptfs_headers("tests/shlkfs_adduser.formated.test.shlkfs");

    // ! Check if second key storage buf is empty
    // cr_assert_arr_eq(shlkfs->keys_storage[1].aes_key_ciphered,
    //                  (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
    //                  AES_KEY_SIZE_BYTES);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        my_rsa, "tests/shlkfs_adduser.formated.my_public.pem",
        "tests/shlkfs_adduser.formated.my_private.pem", NULL);
    write_rsa_keys_on_disk(other_rsa,
                           "tests/shlkfs_adduser.formated.other_public.pem",
                           NULL, NULL);

    cryptfs_adduser("tests/shlkfs_adduser.formated.test.shlkfs",
                    "tests/shlkfs_adduser.formated.other_public.pem",
                    "tests/shlkfs_adduser.formated.my_private.pem");

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers("tests/shlkfs_adduser.formated.test.shlkfs");

    // ! Check if second key storage buf is not empty
    // cr_assert_arr_neq(shlkfs->keys_storage[1].aes_key_ciphered,
    //                   (unsigned char[AES_KEY_SIZE_BYTES]){ 0 },
    //                   AES_KEY_SIZE_BYTES);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);

    return 0;
}

#pragma GCC diagnostic pop
