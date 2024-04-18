#ifndef ENTRIES_H
#define ENTRIES_H

#include "cryptfs.h"

/**
 * @param size Entry size field.
 * @return The number of blocks needed to stock [size] bytes.
 */
int __blocks_needed_for_file(size_t size);

/**
 * @param size Entry size field.
 * @return The number of blocks needed to stock [size] entries in a directory.
 */
int __blocks_needed_for_dir(size_t size);

/**
 * @brief Modify an cryptFS_entry size. Equivalent to Linux truncate syscall.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param directory_index Index of the entry in the current CryptFS_Directory.
 * @param new_size The new size for the entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_truncate(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t new_size);

/**
 * @brief Write a buffer to an entry from a specific index.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param directory_index Index of the entry in the current CryptFS_Directory.
 * @param start_from The start index (in bytes) to begin writing.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer_from(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t start_from, const void* buffer, size_t count);

/**
 * @brief Write a buffer to an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param directory_index Index of the entry in the current CryptFS_Directory.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, const void* buffer, size_t count);

/**
 * @brief Read raw data from an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param directory_index Index of the entry in the current CryptFS_Directory.
 * @param start_from The start index (in bytes) to begin reading.
 * @param buf The buffer to store the read data.
 * @param count The maximum size to read.
 * @return The actual size read on success, or BLOCK_ERROR otherwise.
 */
ssize_t entry_read_raw_data(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t start_from, void* buf, size_t count);

/**
 * @brief Delete an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param parent_directory_index Index of the entry in the current CryptFS_Directory.
 * @param entry_index Index of the entry in the parent directory.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_delete(unsigned char* aes_key, block_t directory_block,
     uint32_t parent_directory_index, uint32_t entry_index);

/**
 * @brief Create an empty file.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param parent_directory_index Index of the entry in the current CryptFS_Directory.
 * @param name The name of the file to create.
 * @return Index where the file entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_empty_file(unsigned char* aes_key, block_t directory_block, uint32_t parent_directory_index, const char* name);

/**
 * @brief Create a directory.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param parent_directory_index Index of the entry in the current CryptFS_Directory.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_directory(unsigned char* aes_key, block_t directory_block, uint32_t parent_directory_index, const char* name);

/**
 * @brief Create a hardlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param parent_directory_index Index of the entry in the current CryptFS_Directory.
 * @param target_link_block Equivalent to `directory_block` but for the targeted entry file.
 * @param target_link_index Index of the target entry file in the current CryptFS_Directory.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_hardlink(unsigned char* aes_key, block_t directory_block,
     uint32_t parent_directory_index, const char* name, block_t target_link_block,
         uint32_t target_link_index);
/**
 * @brief Create a symlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param directory_block The block number where starts a struct CryptFS_Directory.
 * @param parent_directory_index Index of the entry in the current CryptFS_Directory.
 * @param name Name of the symlink.
 * @param symlink The string corresponding to the symlink's path.
 * @return Index where the symlink entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_symlink(unsigned char* aes_key, block_t directory_block,
     uint32_t parent_directory_index, const char* name, const char *symlink);

#endif
