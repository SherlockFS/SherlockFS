#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "cryptfs.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "xalloc.h"

int cryptfs_getattr(const char *path, struct stat *stbuf)
{
    printf("[getattr] Called\n");
    printf("\tAttributes of %s requested\n", path);

    // Init the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Allocate struct for reading directory_block
    struct CryptFS_Entry *entry =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    // Check root directory metadata
    read_blocks_with_decryption(fpi_get_master_key(), ROOT_DIR_BLOCK, 1, entry);
    fpi_clear_decoded_key();

    printf("Name of the block : %s is used %i\n", entry->name, entry->used);
    printf("used %i\ntype %i\n start_block %lu\nname %s\n size %lu\n uid "
           "%u\ngid %u\nmode %u\natime %u\nmtime %u\nctime %u\n",
           entry->used, entry->type, entry->start_block, entry->name,
           entry->size, entry->uid, entry->gid, entry->mode, entry->atime,
           entry->mtime, entry->ctime);

    // TODO search path in blocks

    if (entry->type == ENTRY_TYPE_DIRECTORY)
    {
        stbuf->st_mode = 0755;
        stbuf->st_nlink = 2;
    }
    else if (entry->type == ENTRY_TYPE_FILE)
    {
        stbuf->st_mode = 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = entry->size;
    }
    else
    {
        free(entry);
        return -ENOENT;
    }

    stbuf->st_uid = entry->uid;
    stbuf->st_gid = entry->gid;
    stbuf->st_atime = entry->atime;
    stbuf->st_mtime = entry->mtime;
    free(entry);

    return 0;
}
