#ifndef FUSE_OPERATIONS_H
#define FUSE_OPERATIONS_H

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

/**
 * @brief Closes a file.
 *
 * @param path The path of the file.
 * @param file Pointer to the fuse_file_info structure containing file
 * @return int 0 on success, -1 on failure.
 */
int cryptfs_release(const char *path, struct fuse_file_info *file);

/**
 * @brief Release a directory.
 *
 * @param path The path of the directory to be released.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_releasedir(const char *path, struct fuse_file_info *file);

/**
 * @brief Create a file.
 *
 * @param path The path of the file to be created.
 * @param mode The file mode.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_create(const char *path, mode_t mode, struct fuse_file_info *file);

/**
 * @brief Truncate a file.
 *
 * @param path The path of the file to be truncated.
 * @param offset The offset to truncate the file to.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_ftruncate(const char *path, off_t offset,
                      struct fuse_file_info *file);

/**
 * @brief Check file access permissions.
 *
 * @param path The path of the file to check.
 * @param mode The access mode.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_access(const char *path, int mode);

/**
 * @brief Flush the file.
 *
 * @param path The path of the file to be flushed.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_flush(const char *path, struct fuse_file_info *file);

/**
 * @brief Sync the file.
 *
 * @param path The path of the file to be synced.
 * @param datasync If non-zero, only the user data should be flushed, not the
 * metadata.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_fsync(const char *path, int datasync, struct fuse_file_info *file);

/**
 * @brief Sync the directory.
 *
 * @param path The path of the directory to be synced.
 * @param datasync If non-zero, only the user data should be flushed, not the
 * metadata.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_fsyncdir(const char *path, int datasync,
                     struct fuse_file_info *file);

/**
 * @brief Change the mode of a file.
 *
 * @param path The path of the file to change the mode of.
 * @param mod The new mode.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_chmod(const char *path, mode_t mod);

/**
 * @brief Change the owner and group of a file.
 *
 * @param path The path of the file to change the owner and group of.
 * @param uid The new user ID.
 * @param gid The new group ID.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_chown(const char *path, uid_t uid, gid_t gid);

/**
 * @brief Rename a file or directory.
 *
 * @param path The path of the file or directory to be renamed.
 * @param name The new name.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_rename(const char *path, const char *name);

/**
 * @brief Allocate space for a file.
 *
 * @param path The path of the file to allocate space for.
 * @param mode The mode.
 * @param offset The offset.
 * @param length The length.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_fallocate(const char *path, int mode, off_t offset, off_t length,
                      struct fuse_file_info *file);

/**
 * @brief Write data from a buffer to a file.
 *
 * @param path The path of the file to write to.
 * @param buf Pointer to the fuse_bufvec structure containing the buffer.
 * @param off The offset.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t off,
                      struct fuse_file_info *file);

/**
 * @brief Read data from a file into a buffer.
 *
 * @param path The path of the file to read from.
 * @param bufp Pointer to the fuse_bufvec structure to store the buffer.
 * @param size The size of the buffer.
 * @param off The offset.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size,
                     off_t off, struct fuse_file_info *file);

/**
 * @brief Open a directory.
 *
 * @param path The path of the directory to open.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_opendir(const char *path, struct fuse_file_info *file);

/**
 * @brief Destroy the file system.
 *
 * @param userdata Pointer to the file system data.
 */
void cryptfs_destroy(void *userdata);

/**
 * @brief Get file system statistics.
 *
 * @param path The path of the file system.
 * @param stats Pointer to the statvfs structure to store the statistics.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_statfs(const char *path, struct statvfs *stats);

/**
 * @brief Create a directory.
 *
 * @param path The path of the directory to be created.
 * @param mode The directory mode.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_mkdir(const char *path, mode_t mode);

/**
 * @brief Create a special file.
 *
 * @param path The path of the special file to be created.
 * @param mode The file mode.
 * @param num The device number.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_mknod(const char *path, mode_t mode, dev_t num);

/**
 * @brief Remove a directory.
 *
 * @param path The path of the directory to be removed.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_rmdir(const char *path);

/**
 * @brief Remove a file.
 *
 * @param path The path of the file to be removed.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_unlink(const char *path);

/**
 * @brief Create a symbolic link.
 *
 * @param target The target of the symbolic link. (The string)
 * @param path The path of the symbolic link to be created.
 * (The path of the inode)
 * @return 0 on success, -errno on failure.
 */
int cryptfs_symlink(const char *target, const char *path);

/**
 * @brief Create a hard link.
 *
 * @param oldpath The path of the file to be linked.
 * @param newpath The path of the new link.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_link(const char *oldpath, const char *newpath);

/**
 * @brief Change the mode of a file.
 *
 * @param path The path of the file to change the mode of.
 * @param mode The new mode.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_chmod(const char *path, mode_t mode);

/**
 * @brief Change the owner and group of a file.
 *
 * @param path The path of the file to change the owner and group of.
 * @param uid The new user ID.
 * @param gid The new group ID.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_chown(const char *path, uid_t uid, gid_t gid);

/**
 * @brief Truncate a file.
 *
 * @param path The path of the file to be truncated.
 * @param offset The offset to truncate the file to.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_truncate(const char *path, off_t offset);

/**
 * @brief Get file system statistics.
 *
 * @param path The path of the file system.
 * @param stats Pointer to the statvfs structure to store the statistics.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_statfs(const char *path, struct statvfs *stats);

/**
 * @brief Set an extended attribute.
 *
 * @param path The path of the file to set the attribute on.
 * @param name The name of the attribute.
 * @param value The value of the attribute.
 * @param size The size of the value.
 * @param flags The flags.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_setxattr(const char *path, const char *name, const char *value,
                     size_t size, int flags);

                
/**
 * @brief Get an extended attribute.
 *
 * @param path The path of the file to get the attribute from.
 * @param name The name of the attribute.
 * @param value The value of the attribute.
 * @param size The size of the value.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_getxattr(const char *path, const char *name, char *value,
                     size_t size);

                     /**
 * @brief List extended attributes.
 *
 * @param path The path of the file.
 * @param list The list of attributes.
 * @param size The size of the list.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_listxattr(const char *path, char *list, size_t size);

/**
 * @brief Remove an extended attribute.
 *
 * @param path The path of the file to remove the attribute from.
 * @param name The name of the attribute.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_removexattr(const char *path, const char *name);

/**
 * @brief Sync the directory.
 *
 * @param path The path of the directory to be synced.
 * @param datasync If non-zero, only the user data should be flushed, not the
 * metadata.
 * @param file Pointer to the fuse_file_info structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_fsyncdir(const char *path, int datasync,
                     struct fuse_file_info *file);

/**
 * @brief Lock a file.
 *
 * @param path The path of the file to lock.
 * @param file Pointer to the fuse_file_info structure.
 * @param cmd The lock command.
 * @param lock The lock structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_lock(const char *path, struct fuse_file_info *file, int cmd,
                 struct flock *lock);

/**
 * @brief Set the access and modification times of a file.
 *
 * @param path The path of the file.
 * @param tv The times.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_utimens(const char *path, const struct timespec tv[2]);

/**
 * @brief Get the block mapping.
 *
 * @param path The path of the file.
 * @param blocksize The size of the block.
 * @param idx The index.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_bmap(const char *path, size_t blocksize, uint64_t *idx);

/**
 * @brief Perform I/O control operations on a file.
 *
 * @param path The path of the file.
 * @param cmd The command.
 * @param arg The argument.
 * @param file Pointer to the fuse_file_info structure.
 * @param flags The flags.
 * @param data The data.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_ioctl(const char *path, int cmd, void *arg,
                  struct fuse_file_info *file, unsigned int flags, void *data);

/**
 * @brief Poll for I/O readiness events.
 *
 * @param path The path of the file.
 * @param file Pointer to the fuse_file_info structure.
 * @param ph The poll handle.
 * @param revents The events.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_poll(const char *path, struct fuse_file_info *file, struct fuse_pollhandle *ph, unsigned *revents);

/**
 * @brief Lock a file.
 *
 * @param path The path of the file to lock.
 * @param file Pointer to the fuse_file_info structure.
 * @param cmd The lock command.
 * @param lock The lock structure.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_flock(const char *path, struct fuse_file_info *file, int cmd);

//     .readlink = cryptfs_readlink,

/**
 * @brief Read the target of a symbolic link.
 *
 * @param path The path of the symbolic link.
 * @param buf The buffer to store the target.
 * @param size The size of the buffer.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_readlink(const char *path, char *buf, size_t size);

//     .utime = cryptfs_utime,

/**
 * @brief Set the access and modification times of a file.
 *
 * @param path The path of the file.
 * @param buf The times.
 * @return 0 on success, -errno on failure.
 */
int cryptfs_utime(const char *path, struct utimbuf *buf);

/**
 * @brief Moves the read/write file offset within the file.
 * 
 * @param path The path of the file
 * @param off The offset to move to
 * @param whence The reference point for the offset
 * @param file Pointer to the fuse_file_info structure.
 * @return The new offset on success, -errno on failure
 */
// off_t crypfs_lseek(const char *path, off_t off, int whence, struct fuse_file_info *file);


#endif /* FUSE_OPERATIONS_H */

