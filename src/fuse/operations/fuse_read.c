#include <stdio.h>

#include "cryptfs.h"
#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"

int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
                 struct fuse_file_info *file)
{
    // TODO check error
    printf("--> Trying to read %s, %lu, %lu\n", path, offset, sz);
    ssize_t byte_read;

    struct CryptFS_Entry_ID eid = search_entry(path);
    fpi_clear_decoded_key();

    byte_read = entry_read_raw_data(fpi_get_master_key(), eid, offset, buf, sz);
    if (byte_read == BLOCK_ERROR)
        return -1;
    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    (void)file;
    return byte_read;
}
