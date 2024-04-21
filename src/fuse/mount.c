#include "mount.h"

#include <stdlib.h>

#include "entries.h"
#include "fat.h"
#include "helpers.h"
#include "xalloc.h"

struct fuse_operations cryptfs_ops = {
    .init = cryptfs_init,
    .getattr = cryptfs_getattr,
    .readdir = cryptfs_readdir,
    .open = cryptfs_open,
    .read = cryptfs_read,
};

struct infos fuse_info = {
    .aes_key = NULL,
    .current_directory_block = ROOT_DIR_BLOCK,
    .current_directory_index = 0,
};

int start_fuse(unsigned char *aes_key, int argc, char *argv[])
{
    int ret;

    // Set aes key
    fuse_info.aes_key = aes_key;

    // Start FUSE
    ret = fuse_main(argc, argv, &cryptfs_ops, NULL);
    return ret;
}

void *cryptfs_init(struct fuse_conn_info *info)
{
    printf("Using FUSE protocol %d.%d\n", info->proto_major, info->proto_minor);
    return NULL;
}

int cryptfs_getattr(const char *path, struct stat *stbuf)
{
    printf("[getattr] Called\n");
    printf("\tAttributes of %s requested\n", path);

    // Init the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Allocate struct for reading directory_block
    struct CryptFS_Entry *entry =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    // Check root directory metadata
    read_blocks_with_decryption(fuse_info.aes_key, ROOT_DIR_BLOCK, 1, entry);

    printf("Name of the block : %s is used %i\n", entry->name, entry->used);
    printf("used %i\ntype %i\n start_block %lu\nname %s\n size %lu\n uid "
           "%u\ngid %u\nmode %u\natime %u\nmtime %u\nctime %u\n",
           entry->used, entry->type, entry->start_block, entry->name,
           entry->size, entry->uid, entry->gid, entry->mode, entry->atime,
           entry->mtime, entry->ctime);

    // TODO search path in blocks

    if (entry->type == ENTRY_TYPE_DIRECTORY)
    {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else if (entry->type == ENTRY_TYPE_FILE)
    {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = entry->size;
    }
    else
    {
        free(entry);
        return -ENOENT;
    }

    stbuf->st_uid = entry->uid;
    stbuf->st_gid = entry->gid;
    stbuf->st_atime = entry->atime;
    stbuf->st_mtime = entry->mtime;
    free(entry);

    return 0;
}

int cryptfs_open(const char *path, struct fuse_file_info *file)
{
    printf("call to crysfs_open at path %s", path);
    (void)file;

    return 0;
}

int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
                 struct fuse_file_info *file)
{
    // TODO check error
    printf("--> Trying to read %s, %lu, %lu\n", path, offset, sz);
    ssize_t byte_read;

    struct CryptFS_Entry entry;
    search_entry(path, entry);
    struct CryptFS_Entry_ID entry_id;
    __search_entry_in_directory(fuse_info.aes_key, &entry_id);

    byte_read =
        entry_read_raw_data(fuse_info.aes_key, entry_id, offset, buf, sz);
    if (byte_read == BLOCK_ERROR)
        return -1;
    (void)path;
    (void)buf;
    (void)sz;
    (void)offset;
    (void)file;
    return byte_read;
}

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
