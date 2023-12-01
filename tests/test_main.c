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

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "print.h"
#include "xalloc.h"

int main(void)
{
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("cfs_adduser.formated.test.cfs");
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

    EVP_PKEY *my_rsa = generate_rsa_keypair();

    format_fs("cfs_adduser.formated.test.cfs", NULL, my_rsa);

    // Read CryptFS structure

    // Check if second key storage buf is empty

    // OpenSSL generate keypair and write it to a file
    EVP_PKEY *other_rsa = generate_rsa_keypair();
    write_rsa_keys_on_disk(my_rsa, "cfs_adduser.formated.my_public.pem",
                           "cfs_adduser.formated.my_private.pem", NULL);
    write_rsa_keys_on_disk(other_rsa, "cfs_adduser.formated.other_public.pem",
                           NULL, NULL);

    return 0;
}
