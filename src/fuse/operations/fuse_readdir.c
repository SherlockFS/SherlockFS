#include <stdio.h>

#include "cryptfs.h"
#include "print.h"
#include "fuse_mount.h"

int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi)
{
    print_debug("readdir() called\n");

    filler(buf, ".", NULL, 0); // Current Directory
    filler(buf, "..", NULL, 0); // Parent Directory

    (void)path;
    (void)buf;
    (void)filler;
    (void)offset;
    (void)fi;
    return 0;
}
