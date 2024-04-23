#include <stdio.h>

#include "fuse_mount.h"

int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
                  struct fuse_file_info *file)
{
    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    (void)file;
    printf("Write syscall\n");
    return 0;
}
