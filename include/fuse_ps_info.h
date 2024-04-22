#ifndef FUSE_PS_INFO_H
#define FUSE_PS_INFO_H

// Minimum file descriptor value (0, 1 and 2 are reserved for stdin, stdout and
// stderr)
#define FD_MIN 3

#include <block.h>
#include <stdbool.h>

// ------------------- File descriptor management -------------------

/**
 * @brief File (not inode) information structure.
 *
 * @note This structure is passed to the FUSE fh (file handle) parameter.
 *
 * This structure contains information about a file in the process memory
 * (file).
 */
struct fs_file_info
{
    int fd; // File descriptor of the files
    struct CryptFS_Entry_ID uid; // SherlockFS unique entry identifier
    size_t seek_offset; // Current seek offset
    struct fs_file_info *next; // Pointer to the next file info node (SherlockFS
                               // internal use, not FUSE)
};

/** @brief Ask a new file descriptor to SherlockFS process.
 *
 * This function returns a new file descriptor for the file system. The returned
 * file descriptor can be used to perform various operations on the file.
 *
 * @return A pointer to the newly allocated `struct fs_file_info` object. If
 * there is no more file descriptors available, `NULL` is returned and `errno`
 * is set to `EMFILE`.
 */
struct fs_file_info *ffi_get_new_fd();

/**
 * @brief Release a file descriptor.
 *
 * This function releases the given file descriptor and frees the associated
 * resources. After calling this function, the file descriptor should no longer
 * be used.
 *
 * @param file The `struct fs_file_info` object representing the file descriptor
 * to release.
 *
 * @note If the file descriptor is invalid, `errno` is set to `EBADF`.
 */
void ffi_release_fd(struct fs_file_info *file);

// ------------------- File system information management -------------------

/**
 * @brief Sets the AES key for the file system into memory.
 *
 * @note The master key is XOR encrypted in memory in order to prevent easy loot
 * in case of memory corruption.
 *
 * @param key The AES key to set. In order to better control where the master
 * key is in memory, its value is zeroed after being registered (so don't use it
 * after this, call fpi_get_master_key() instead).
 */
void fpi_set_master_key(unsigned char *key);

/**
 * @brief Retrieves the AES key of the file system from memory.
 *
 * @warning You must use fpi_clear_decoded_key() just after using this function.
 * @warning Also avoid copying the key to another memory location.
 *
 * @return The AES key.
 */
const char *fpi_get_master_key();

/**
 * @brief Zeroes the decoded key in memory.
 */
void fpi_clear_decoded_key();

/**
 * @brief Sets the current directory block for the file system into memory.
 *
 * @param block The block number to set.
 */
void fpi_set_current_directory_block(block_t block);

/**
 @brief Retrieves the current directory block of the file system from memory.
 *
 * @param info The file system's persistent information structure.
 * @return The current directory block number.
 */
block_t fpi_get_current_directory_block();

#endif /* FUSE_PS_INFO_H */
