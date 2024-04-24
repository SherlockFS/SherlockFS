#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"

int cryptfs_open(const char *path, struct fuse_file_info *file)
{
    print_debug("open() called\n");

    // FD management / allocation
    struct fs_file_info *ffi = ffi_get_new_fd();
    if (!ffi)
        return -EMFILE; // No more file descriptors available

    // open() flags management
    if ((file->flags & O_ACCMODE) == O_RDONLY) // Read only
        ffi->is_readable_mode = true;
    else if ((file->flags & O_ACCMODE) == O_WRONLY) // Write only
        ffi->is_writable_mode = true;
    else // ((file->flags & O_ACCMODE) == O_RDWR) // Read and write
    {
        ffi->is_readable_mode = true;
        ffi->is_writable_mode = true;
    }

    // File open / creation management
    struct CryptFS_Entry_ID *entry_id = NULL;
    if (file->flags & O_CREAT)
    {
        // Create the file
        entry_id = create_file_by_path(fpi_get_master_key(), path);
        switch ((uint64_t)entry_id)
        {
        case BLOCK_ERROR:
            ffi_release_fd(ffi);
            return -EIO;
        case ENTRY_NO_SUCH:
            ffi_release_fd(ffi);
            return -ENOENT;
        default:
            break;
        }
    }
    else
    {
        // Open the file
        entry_id = get_entry_by_path(fpi_get_master_key(), path);
        switch ((uint64_t)entry_id)
        {
        case BLOCK_ERROR:
            ffi_release_fd(ffi);
            return -EIO;
        case ENTRY_NO_SUCH:
            ffi_release_fd(ffi);
            return -ENOENT;
        default:
            break;
        }

        fpi_clear_decoded_key();
    }

    ffi->uid = *entry_id;
    ffi->seek_offset = 0;

    file->fh = (uint64_t)ffi; // File handle is the file information structure

    free(entry_id);

    return 0;
}
