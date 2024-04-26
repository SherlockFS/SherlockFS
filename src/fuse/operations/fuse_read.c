#include <errno.h>
#include <stdio.h>

#include "cryptfs.h"
#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"

int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
                 struct fuse_file_info *file)
{
    print_debug("read() called\n");
    print_debug("Trying to read %lu bytes from entry '%s', at offset '%lu'\n",
                sz, path, offset);
    ssize_t byte_read;

    struct CryptFS_Entry_ID *entry_id = (struct CryptFS_Entry_ID *)file->fh;

    byte_read =
        entry_read_raw_data(fpi_get_master_key(), *entry_id, offset, buf, sz);
    fpi_clear_decoded_key();
    if (byte_read == BLOCK_ERROR)
        return -EIO;
    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    return byte_read;
}
