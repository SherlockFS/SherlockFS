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
    set_device_path("tests/blocksize.test.shlkfs");

    struct CryptFS *shlkfs = xcalloc(1, sizeof(struct CryptFS));

    format_fs("tests/blocksize.test.shlkfs", "tests/blocksize.test.pub.pem",
              "tests/blocksize.test.private.pem", NULL, NULL);

    // Change the blocksize
    shlkfs->header.blocksize = 1024;

    // Write the CryptFS to the file
    write_cryptfs_headers("tests/blocksize.test.shlkfs", shlkfs);

    bool a = is_already_formatted("tests/blocksize.test.shlkfs");
    printf("%d\n", a);
    free(shlkfs);

    return 0;
}
