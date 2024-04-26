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
           "of=goto_used_entry_in_directory.30_files_27_29_deleted.test."
           "shlkfs "
           "bs=4096 count=100");

    set_device_path(
        ""
        "goto_used_entry_in_directory.30_files_27_29_deleted.test.shlkfs");

    format_fs("goto_used_entry_in_directory.30_files_27_29_deleted.test.shlkfs",
              "goto_used_entry_in_directory.30_files_27_29_deleted.public.pem",
              "goto_used_entry_in_directory.30_files_27_29_deleted.private.pem",
              NULL, NULL);

    fpi_register_master_key_from_path(
        "goto_used_entry_in_directory.30_files_27_29_deleted.test.shlkfs",
        ""
        "goto_used_entry_in_directory.30_files_27_29_deleted.private.pem");

    struct CryptFS_Entry_ID root_dirctory_entry_id = { .directory_block =
                                                           ROOT_ENTRY_BLOCK,
                                                       .directory_index = 0 };

    struct CryptFS_Entry_ID
        *entry_ids[30]; // [0,29]: [0, 24] used, [25, 28] unused, 29 used
    for (int i = 0; i < 30; i++)
    {
        char path[100];
        sprintf(path, "/test_file%d", i);
        entry_ids[i] = create_file_by_path(fpi_get_master_key(), path);
    }

    for (int i = 26; i < 28; i++)
    {
        char path[100];
        sprintf(path, "/test_file%d", i);
        printf("Deleting %s\n", path);
        delete_entry_by_path(fpi_get_master_key(), path);

        // Check all entries if any is deleted
        for (int j = 0; j < 30; j++)
        {
            if (entry_ids[j] != NULL)
            {
                char path_2[100];
                sprintf(path_2, "/test_file%d", j);
                struct CryptFS_Entry_ID *entry_id =
                    get_entry_by_path(fpi_get_master_key(), path_2);

                // Get entry by ID
                struct CryptFS_Entry *entry =
                    get_entry_from_id(fpi_get_master_key(), *entry_id);

                if (entry->used == 0)
                {
                    printf("Entry %d is deleted\n", j);
                    entry_ids[j] = NULL;
                }
            }
        }
    }

    // Ask entry index 25, must return 25
    struct CryptFS_Entry_ID *entry_id_test_file25 =
        goto_used_entry_in_directory(fpi_get_master_key(),
                                     root_dirctory_entry_id, 25);
    // Index 25 entry
    goto_entry_in_directory(fpi_get_master_key(), entry_ids[25]);

    (void)entry_ids;
    (void)entry_id_test_file25;
    return 0;
}
