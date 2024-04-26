#include <fcntl.h>
#include <stdlib.h>

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
    struct CryptFS_Entry_ID *directory_entry_id =
        (struct CryptFS_Entry_ID *)fi->fh;

    // Get entry from the entry ID
    struct CryptFS_Entry *directory_entry =
        get_entry_from_id(fpi_get_master_key(), *directory_entry_id);

    filler(buf, ".", NULL, 0); // Current Directory
    filler(buf, "..", NULL, 0); // Parent Directory
    for (uint64_t i = offset; i < directory_entry->size; i++)
    {
        // goto_used_entry_in_directory
        struct CryptFS_Entry_ID *entry_id = goto_used_entry_in_directory(
            fpi_get_master_key(), *directory_entry_id, i);

        // Get entry from the entry ID
        struct CryptFS_Entry *entry =
            get_entry_from_id(fpi_get_master_key(), *entry_id);

        struct stat stbuf;
        stbuf.st_mode = entry->mode;
        stbuf.st_nlink = 1;
        stbuf.st_uid = entry->uid;
        stbuf.st_gid = entry->gid;
        stbuf.st_size = entry->size;
        stbuf.st_atime = entry->atime;
        stbuf.st_mtime = entry->mtime;
        stbuf.st_ctime = entry->ctime;

        filler(buf, entry->name, &stbuf, 0);

        free(entry_id);
        free(entry);
    }

    free(directory_entry);

    return 0;

    // // TODO: IMPLEMENT readdir

    // // Create fake file stbuf
    // static struct stat stbuf;
    // stbuf.st_mode = __S_IFREG | 0755;
    // stbuf.st_nlink = 2;
    // stbuf.st_uid = 1000;
    // stbuf.st_gid = 1000;
    // stbuf.st_size = 1024;
    // stbuf.st_atime = time(NULL);
    // stbuf.st_mtime = time(NULL);
    // stbuf.st_ctime = time(NULL);

    // filler(buf, "file1", &stbuf, 0);
    (void)path;
    (void)buf;
    (void)filler;
    (void)offset;
    (void)fi;
    return 0;
}
