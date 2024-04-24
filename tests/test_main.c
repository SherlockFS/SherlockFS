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
           "of=create_hardlink_by_path.root.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("create_hardlink_by_path.root.test.shlkfs");

    format_fs("create_hardlink_by_path.root.test.shlkfs",
              "create_hardlink_by_path.root.public.pem",
              "create_hardlink_by_path.root.private.pem", NULL, NULL);

    fpi_register_master_key_from_path(
        "create_hardlink_by_path.root.test.shlkfs",
        "create_hardlink_by_path.root.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        create_file_by_path(fpi_get_master_key(), "/test_hardlink_target");

    // Create hardlink and remember its entry ID
    struct CryptFS_Entry_ID *hardlink_entry_id = create_hardlink_by_path(
        fpi_get_master_key(), "/test_hardlink", "/test_hardlink_target");

    (void)entry_id;
    (void)hardlink_entry_id;
    return 0;
}
