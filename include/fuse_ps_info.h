#ifndef FUSE_PS_INFO_H
#define FUSE_PS_INFO_H

// Minimum file descriptor value (0, 1 and 2 are reserved for stdin, stdout and
// stderr)
#define FD_MIN 3

#include <block.h>
#include <stdbool.h>

#include "cryptfs.h"

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
    struct CryptFS_Entry_ID uid; // SherlockFS unique entry identifier
    size_t seek_offset; // Current seek offset
    bool is_readable_mode; // Whether the file is open for reading
    bool is_writable_mode; // Whether the file is open for writing
    struct fs_file_info *next; // Pointer to the next file info node (SherlockFS
                               // internal use, not FUSE)
};

// ------------------- File system information management -------------------

/**
 * @brief Sets the AES key for the file system into memory from a device and a
 * private key path.
 *
 * @note The master key is XOR encrypted in memory in order to prevent easy loot
 * in case of memory corruption.
 *
 * @param device_path The path to the device where the master key is stored.
 * @param private_key_path The path to the private key used to decrypt the
 * master key.
 */
void fpi_register_master_key_from_path(const char *device_path,
                                       const char *private_key_path);

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
void fpi_register_master_key(unsigned char *key);

/**
 * @brief Retrieves the AES key of the file system from memory.
 *
 * @warning You must use fpi_clear_decoded_key() just after using this function.
 * @warning Also avoid copying the key to another memory location.
 *
 * @return The AES key. NULL if the key is not set.
 */
const unsigned char *fpi_get_master_key();

/**
 * @brief Zeroes the decoded key in memory.
 */
void fpi_clear_decoded_key();

#endif /* FUSE_PS_INFO_H */
