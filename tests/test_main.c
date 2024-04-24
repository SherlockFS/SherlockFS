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
#include "fuse_ps_info.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

int main(void)
{
    system("dd if=/dev/zero "
           "of=get_entry_by_path.create_single_file.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("get_entry_by_path.create_single_file.test.shlkfs");

    format_fs("get_entry_by_path.create_single_file.test.shlkfs",
              "get_entry_by_path.create_single_file.public.pem",
              "get_entry_by_path.create_single_file.private.pem", NULL, NULL);

    fpi_register_master_key_from_path(
        "get_entry_by_path.create_single_file.test.shlkfs",
        "get_entry_by_path.create_single_file.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    assert(entry_id->directory_block == ROOT_ENTRY_BLOCK);
    assert(entry_id->directory_index == 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id, "test_file");

    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_file");

    (void)entry_id_test_file;
    return 0;
}
