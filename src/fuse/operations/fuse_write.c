#include <stdio.h>

#include "fuse_mount.h"
#include "print.h"

int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
                  struct fuse_file_info *file)
{
    print_debug("write() called\n");

    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    (void)file;
    printf("Write syscall\n");
    return 0;
}
