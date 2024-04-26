#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"

int cryptfs_release(const char *path, struct fuse_file_info *file)
{
    print_debug("release(path=%s, file=%p)\n", path, file);

    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    if (ffi)
        free(ffi);

    return 0;
}
