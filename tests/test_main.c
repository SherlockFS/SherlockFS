#include <assert.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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

int main(void)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/cfs_adduser.already_exists.test.cfs");
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

    EVP_PKEY *my_rsa = generate_rsa_keypair();
    EVP_PKEY *other_rsa = generate_rsa_keypair();

    format_fs("build/tests/cfs_adduser.already_exists.test.cfs", NULL, NULL,
              NULL, my_rsa);

    // Read CryptFS structure
    struct CryptFS *cfs =
        read_cryptfs_headers("build/tests/cfs_adduser.already_exists.test.cfs");

    write_rsa_keys_on_disk(
        my_rsa, "build/tests/cfs_adduser.already_exists.my_public.pem",
        "build/tests/cfs_adduser.already_exists.my_private.pem", NULL);
    write_rsa_keys_on_disk(
        other_rsa, "build/tests/cfs_adduser.already_exists.other_public.pem",
        NULL, NULL);

    int cfs_ret = 0;
    for (u_int8_t i = 0; i < 2; i++) // Add the same user twice
        cfs_ret =
            cryptfs_adduser("tests/cfs_adduser.already_exists.test.cfs",
                            "tests/cfs_adduser.already_exists.other_public.pem",
                            "tests/cfs_adduser.already_exists.my_private.pem");

    // Read CryptFS structure
    free(cfs);
    cfs =
        read_cryptfs_headers("build/tests/cfs_adduser.already_exists.test.cfs");

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(cfs);

    (void)cfs_ret; // Avoid unused variable warning (cfs_ret is used in assert)

    return 0;
}
