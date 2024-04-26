#include <fcntl.h>
#include <stdio.h>

#include "cryptfs.h"
#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"

int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi)
{
    print_debug("readdir(path=%s, buf=%p, filler=%p, offset=%ld, fi=%p)\n",
                path, buf, filler, offset, fi);

    // Get the entry ID of the directory
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);
    (void)entry_id;

    // TODO: IMPLEMENT readdir

    // Create fake file stbuf
    static struct stat stbuf;
    stbuf.st_mode = __S_IFREG | 0755;
    stbuf.st_nlink = 2;
    stbuf.st_uid = 1000;
    stbuf.st_gid = 1000;
    stbuf.st_size = 1024;
    stbuf.st_atime = time(NULL);
    stbuf.st_mtime = time(NULL);
    stbuf.st_ctime = time(NULL);

    filler(buf, ".", NULL, 0); // Current Directory
    filler(buf, "..", NULL, 0); // Parent Directory
    filler(buf, "file1", &stbuf, 0);
    (void)path;
    (void)buf;
    (void)filler;
    (void)offset;
    (void)fi;
    return 0;
}
