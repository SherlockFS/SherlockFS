#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "cryptfs.h"
#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"
#include "xalloc.h"

int cryptfs_getattr(const char *path, struct stat *stbuf)
{
    print_debug("getattr(path=%s, stbuf=%p)\n", path, stbuf);
    // Init the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Allocate struct for reading directory_block
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    switch ((uint64_t)entry_id)
    {
    case BLOCK_ERROR:
        return -EIO;
    case ENTRY_NO_SUCH:
        return -ENOENT;
    default:
        break;
    }

    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);
    fpi_clear_decoded_key();

    free(entry_id);

    if (entry->type == ENTRY_TYPE_DIRECTORY)
        stbuf->st_mode = __S_IFDIR | entry->mode;

    else if (entry->type == ENTRY_TYPE_FILE
             || entry->type == ENTRY_TYPE_HARDLINK)
        stbuf->st_mode = __S_IFREG | entry->mode;
    
    else if (entry->type == ENTRY_TYPE_SYMLINK)
        stbuf->st_mode = __S_IFLNK | entry->mode;
    else
    {
        free(entry);
        return -ENOENT;
    }

    stbuf->st_nlink = 1; // TODO: Number of hardlinks
    stbuf->st_uid = entry->uid;
    stbuf->st_gid = entry->gid;
    stbuf->st_atime = entry->atime;
    stbuf->st_mtime = entry->mtime;
    stbuf->st_ctime = entry->ctime;
    stbuf->st_size = entry->size;
    free(entry);

    print_debug("getattr() finished\n");

    return 0;
}
