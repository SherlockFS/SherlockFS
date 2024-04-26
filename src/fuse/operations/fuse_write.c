#include <stdio.h>

#include "fuse_mount.h"
#include "print.h"

int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
                  struct fuse_file_info *file)
{
    print_debug("write(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p)\n", path,
                buf, sz, offset, file);

    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    (void)file;
    return 1;
}
