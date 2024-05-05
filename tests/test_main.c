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
#include "entries.h"
#include "fat.h"
#include "format.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

int main(void)
{
    system("dd if=/dev/zero "
           "of=/home/nathan/epita/SherlockFS/build/test_main.shlkfs bs=4096 "
           "count=100");

    format_fs("/home/nathan/epita/SherlockFS/build/test_main.shlkfs",
              "/home/nathan/.sherlockfs/public.pem",
              "/home/nathan/.sherlockfs/private.pem", NULL, NULL);

    set_device_path("/home/nathan/epita/SherlockFS/build/test_main.shlkfs");

    fpi_register_master_key_from_path(
        "/home/nathan/epita/SherlockFS/build/test_main.shlkfs",
        "/home/nathan/.sherlockfs/private.pem");

    struct fuse_file_info ffi;
    struct stat stbuf;
    int a;
    a = cryptfs_create("/test.txt", 0644, &ffi);
    a = cryptfs_mkdir("/rep", 0755);
    a = cryptfs_mkdir("/rep/dir", 0755);
    a = cryptfs_create("/rep/dir/test2.txt", 0644, &ffi);
    print_debug("cryptfs_create returned %d\n", a);
    return cryptfs_getattr("/rep/dir/test2.txt", &stbuf);
}
