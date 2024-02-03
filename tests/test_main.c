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
#include "deluser.h"
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
    set_device_path("tests/shlkfs_deluser.two_users.test.shlkfs");

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("tests/shlkfs_deluser.two_users.test.shlkfs",
              "tests/shlkfs_deluser.two_users.test.public.pem",
              "tests/shlkfs_deluser.two_users.test.private.pem", NULL, my_rsa);
    assert(is_already_formatted("tests/shlkfs_deluser.two_users.test.shlkfs"));

    // Read CryptFS structure
    struct CryptFS *shlkfs =
        read_cryptfs_headers("tests/shlkfs_deluser.two_users.test.shlkfs");

    // Check if second key storage buf is empty
    assert(shlkfs->keys_storage[1].occupied == 0);

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(other_rsa,
                           "tests/shlkfs_deluser.two_users.other_public.pem",
                           NULL, NULL);

    // Add user
    assert(cryptfs_adduser("tests/shlkfs_deluser.two_users.test.shlkfs",
                           "tests/shlkfs_deluser.two_users.other_public.pem",
                           "tests/shlkfs_deluser.two_users.test.private.pem")
           == 0);

    // Delete the other user
    assert(cryptfs_deluser("tests/shlkfs_deluser.two_users.test.shlkfs",
                           "tests/shlkfs_deluser.two_users.my_private.pem",
                           "tests/shlkfs_deluser.two_users.other_public.pem")
           == 0);

    // Read CryptFS structure
    free(shlkfs);
    shlkfs = read_cryptfs_headers("tests/shlkfs_deluser.two_users.test.shlkfs");

    // Check if second key storage buf is not empty
    assert(shlkfs->keys_storage[1].occupied == 0);

    // Free memory
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(shlkfs);

    return 0;
}

#pragma GCC diagnostic pop
