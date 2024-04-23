#ifndef FUSE_OPERATIONS_H
#define FUSE_OPERATIONS_H

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <sys/stat.h>

/**
 * @brief Initializes the SherlockFS filesystem.
 *
 * This function is called when the filesystem is mounted. It initializes the
 * filesystem and returns a pointer to the private data that will be passed to
 * the other filesystem operations.
 *
 * @param info Pointer to the fuse_conn_info structure containing connection
 *             information.
 * @return Pointer to the private data.
 */
void *cryptfs_init(struct fuse_conn_info *info);

/**
 * @brief Retrieves the attributes of a file or directory.
 *
 * This function is called to retrieve the attributes of a file or directory
 * specified by the given path.
 *
 * @param path The path of the file or directory.
 * @param stbuf Pointer to the stat structure where the attributes will be
 *              stored.
 * @return 0 on success, -1 on failure.
 */
int cryptfs_getattr(const char *path, struct stat *stbuf);

/**
 * @brief Opens a file.
 *
 * This function is called to open a file specified by the given path.
 *
 * @param path The path of the file.
 * @param file Pointer to the fuse_file_info structure containing file
 *             information.
 * @return 0 on success, -1 on failure.
 */
int cryptfs_open(const char *path, struct fuse_file_info *file);

/**
 * @brief Writes data to a file.
 *
 * This function is called to write data to a file specified by the given path.
 *
 * @param path The path of the file.
 * @param buf Pointer to the buffer containing the data to be written.
 * @param sz The size of the data to be written.
 * @param offset The offset within the file where the data should be written.
 * @param file Pointer to the fuse_file_info structure containing file
 *             information.
 * @return The number of bytes written on success, -1 on failure.
 */
int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
                  struct fuse_file_info *file);

/**
 * @brief Reads data from a file.
 *
 * This function is called to read data from a file specified by the given path.
 *
 * @param path The path of the file.
 * @param buf Pointer to the buffer where the read data will be stored.
 * @param sz The size of the buffer.
 * @param offset The offset within the file from where the data should be read.
 * @param file Pointer to the fuse_file_info structure containing file
 *             information.
 * @return The number of bytes read on success, -1 on failure.
 */
int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
                 struct fuse_file_info *file);

/**
 * @brief Reads the contents of a directory.
 *
 * This function is called to read the contents of a directory specified by the
 * given path.
 *
 * @param path The path of the directory.
 * @param buf Pointer to the buffer where the directory entries will be stored.
 * @param filler Function used to add directory entries to the buffer.
 * @param offset The offset within the directory.
 * @param fi Pointer to the fuse_file_info structure containing file
 *           information.
 * @return 0 on success, -1 on failure.
 */
int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi);

// int cryptfs_release(const char *path, struct fuse_file_info *file);
// int cryptfs_releasedir(const char *path, struct fuse_file_info *file);
// int cryptfs_create(const char *path, mode_t mode, struct fuse_file_info
// *file); int cryptfs_ftruncate(const char *path, off_t offset, struct
// fuse_file_info *file); int cryptfs_access(const char *path, int mode);
//
// int cryptfs_flush(const char *path, struct fuse_file_info *file);
// int cryptfs_fsync(const char *path, int, struct fuse_file_info *file);
// int cryptfs_fsyncdir(const char *path, int, struct fuse_file_info *file);
//
// int cryptfs_chmod(const char *path, mode_t mod);
// int cryptfs_chown(const char *path, uid_t uid, gid_t gid);
// int cryptfs_rename(const char *path, const char *name);
//
// int cryptfs_fallocate(const char *path, int, off_t, off_t, struct
// fuse_file_info *file);
// int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t off,
//             struct fuse_file_info *file);
// int cryptfs_read_buf(const char *path, struct fuse_bufvec **bufp,
//             size_t size, off_t off, struct fuse_file_info *file);
// int cryptfs_opendir(const char *path, struct fuse_file_info *file);

// void cryptfs_destroy(void *ptr);
// int cryptfs_statfs(const char *path, struct statvfs *stats);
//
// int cryptfs_mkdir(const char *path, mode_t mode);
// int cryptfs_mknod(const char *path, mode_t mode, dev_t num);
//
// int cryptfs_rmdir(const char *path);

#endif /* FUSE_OPERATIONS_H */
