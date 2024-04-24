#include <stdio.h>
#include <errno.h>

#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "entries.h"

int cryptfs_open(const char *path, struct fuse_file_info *file)
{
    printf("call to crysfs_open at path %s", path);
    (void)file;
        struct CryptFS_Entry_ID *entry_id = get_entry_by_path(fpi_get_master_key(), path);
    fpi_clear_decoded_key();

    if (entry_id == (void*)BLOCK_ERROR)
        return -EIO;
    if (entry_id == (void *)BLOCK_NOT_SUCH_ENTRY)
        return -ENOTDIR;

    // FD management
    struct fs_file_info *ffi = ffi_get_new_fd();
    if (!ffi)
        return -EMFILE;

    ffi->uid = *entry_id;
    ffi->seek_offset = 0;

    file->fh = (uint64_t)ffi; // File handle is the file information structure

    return 0;
}
