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
    print_debug("getattr() called\n");

    // Init the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Allocate struct for reading directory_block
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);
    fpi_clear_decoded_key();

    // Print entry_id fields
    print_debug("Entry ID '%s' block = %ld\n", path, entry_id->directory_block);
    print_debug("Entry ID '%s' index = %d\n", path, entry_id->directory_index);
    free(entry_id);

    // Print all entry fields
    print_debug("Entry '%s' mode = %o\n", path, entry->mode);
    print_debug("Entry '%s' uid = %d\n", path, entry->uid);
    print_debug("Entry '%s' gid = %d\n", path, entry->gid);
    print_debug("Entry '%s' atime = %ld\n", path, entry->atime);
    print_debug("Entry '%s' mtime = %ld\n", path, entry->mtime);
    print_debug("Entry '%s' ctime = %ld\n", path, entry->ctime);
    print_debug("Entry '%s' size = %ld\n", path, entry->size);
    print_debug("Entry '%s' type = %d\n", path, entry->type);
    if (entry->type == ENTRY_TYPE_DIRECTORY)
    {
        print_debug("Entry '%s' is a directory\n", path);
        stbuf->st_mode = __S_IFDIR | entry->mode;
    }

    else if (entry->type == ENTRY_TYPE_FILE
             || entry->type == ENTRY_TYPE_HARDLINK)
    {
        print_debug("Entry '%s' is a file\n", path);
        stbuf->st_mode = __S_IFREG | entry->mode;
    }
    else if (entry->type == ENTRY_TYPE_SYMLINK)
    {
        print_debug("Entry '%s' is a symlink\n", path);
        stbuf->st_mode = __S_IFLNK | entry->mode;
    }
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

    return 0;
}
