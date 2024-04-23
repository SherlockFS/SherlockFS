#include <stdio.h>

#include "cryptfs.h"
#include "fuse_mount.h"

int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi)
{
    printf("--> Getting The List of Files of %s\n", path);

    filler(buf, ".", NULL, 0); // Current Directory
    filler(buf, "..", NULL, 0); // Parent Directory

    (void)buf;
    (void)filler;
    (void)offset;
    (void)fi;
    return 0;
}
