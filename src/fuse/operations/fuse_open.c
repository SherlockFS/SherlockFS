#include <stdio.h>

#include "fuse_mount.h"

int cryptfs_open(const char *path, struct fuse_file_info *file)
{
    printf("call to crysfs_open at path %s", path);
    (void)file;

    return 0;
}
