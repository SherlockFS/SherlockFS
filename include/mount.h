#ifndef MOUNT_H
#define MOUNT_H

#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS  64

#include "cryptfs.h"
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>


int start_fuse(unsigned char *aes_key, int argc, char *argv[]);
void *cryptfs_init(struct fuse_conn_info *info);
//void cryptfs_destroy(void *ptr);
//int cryptfs_statfs(const char *path, struct statvfs *stats);
//
//int cryptfs_mkdir(const char *path, mode_t mode);
//int cryptfs_mknod(const char *path, mode_t mode, dev_t num);
//
//int cryptfs_rmdir(const char *path);
//
int cryptfs_getattr(const char *path, struct stat *stbuf);
int cryptfs_open(const char *path, struct fuse_file_info *file);
int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
            struct fuse_file_info *file);
int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
            struct fuse_file_info *file);
//int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t off,
//            struct fuse_file_info *file);
//int cryptfs_read_buf(const char *path, struct fuse_bufvec **bufp,
//            size_t size, off_t off, struct fuse_file_info *file);
//int cryptfs_opendir(const char *path, struct fuse_file_info *file);
int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi);
//int cryptfs_release(const char *path, struct fuse_file_info *file);
//int cryptfs_releasedir(const char *path, struct fuse_file_info *file);
//int cryptfs_create(const char *path, mode_t mode, struct fuse_file_info *file);
//int cryptfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *file);
//int cryptfs_access(const char *path, int mode);
//
//int cryptfs_flush(const char *path, struct fuse_file_info *file);
//int cryptfs_fsync(const char *path, int, struct fuse_file_info *file);
//int cryptfs_fsyncdir(const char *path, int, struct fuse_file_info *file);
//
//int cryptfs_chmod(const char *path, mode_t mod);
//int cryptfs_chown(const char *path, uid_t uid, gid_t gid);
//int cryptfs_rename(const char *path, const char *name);
//
//int cryptfs_fallocate(const char *path, int, off_t, off_t,
//            struct fuse_file_info *file);

int search_entry(const char *path, struct CryptFS_Entry entry);

struct infos
{
    unsigned char *aes_key;
    block_t current_directory_block;
    uint32_t current_directory_index;
};

#endif /* FUSE_H */
