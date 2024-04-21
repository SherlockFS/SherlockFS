//
// Created by chalu on 4/21/2024.
//

#include "helpers.h"

#include <stdlib.h>

#include "entries.h"
#include "fat.h"
#include "helpers.h"
#include "xalloc.h"

int search_entry(const char *path, struct CryptFS_Entry entry)
{
    printf("Search entry");
    char current_path[ENTRY_NAME_MAX_LEN] = { 0 };
    strcpy(current_path, path);
    (void)entry;
    //    struct CryptFS *shlkfs =
    //            xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
    //                            sizeof(struct CryptFS) + sizeof(struct
    //                            CryptFS_FAT));
    //
    //    struct CryptFS_Entry root_directory = shlkfs->root_directory;
    //    struct CryptFS_FAT first_fat = shlkfs->first_fat;

    //    if (strcmp(path, root_directory.name) == 0) {
    //        entry = root_directory;
    //        return 0;
    //    }
    return -1;
}

int __search_entry_in_directory(unsigned char *aes_key,
                                struct CryptFS_Entry_ID *entry_id)
{
    if (entry_id->directory_index > NB_ENTRIES_PER_BLOCK)
    {
        int count = entry_id->directory_index / NB_ENTRIES_PER_BLOCK;
        entry_id->directory_index =
            entry_id->directory_index % NB_ENTRIES_PER_BLOCK;
        while (count > 1 && read_fat_offset(aes_key, entry_id->directory_block))
        {
            entry_id->directory_block =
                read_fat_offset(aes_key, entry_id->directory_block);
            count--;
        }
        if (count > 1)
            return -1;
    }
    return 0;
}
