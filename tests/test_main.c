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
           "of=delete_entry_by_path.root.test.shlkfs "
           "bs=4096 count=100");

        set_device_path("delete_entry_by_path.root.test.shlkfs");

        format_fs("delete_entry_by_path.root.test.shlkfs",
                  "delete_entry_by_path.root.public.pem",
                  "delete_entry_by_path.root.private.pem", NULL, NULL);

        fpi_register_master_key_from_path(
            "delete_entry_by_path.root.test.shlkfs",
            "delete_entry_by_path.root.private.pem");

        free(create_file_by_path(fpi_get_master_key(), "/test_file"));

        // Delete entry
        assert(delete_entry_by_path(fpi_get_master_key(), "/test_file") == 0);

        // Get entry ID
        struct CryptFS_Entry_ID *entry_id_test_file =
            get_entry_by_path(fpi_get_master_key(), "/test_file");

        // Check if the entry ID is correct
        assert(entry_id_test_file == (void *)ENTRY_NO_SUCH);
        return 0;
}
