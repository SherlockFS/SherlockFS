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
 * @param entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param new_size The new size for the entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_truncate(unsigned char* aes_key, struct CryptFS_Entry_ID entry_id, size_t new_size);

/**
 * @brief Write a buffer to an entry from a specific index.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param start_from The start index (in bytes) to begin writing.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer_from(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id, size_t start_from, const void* buffer, size_t count);

/**
 * @brief Write a buffer to an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id, const void* buffer, size_t count);

/**
 * @brief Read raw data from an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param start_from The start index (in bytes) to begin reading.
 * @param buf The buffer to store the read data.
 * @param count The maximum size to read.
 * @return The actual size read on success, or BLOCK_ERROR otherwise.
 */
ssize_t entry_read_raw_data(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id, size_t start_from, void* buf, size_t count);

/**
 * @brief Delete an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param entry_index Index of the entry to delete in the parent directory.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_delete(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id, uint32_t entry_index);

/**
 * @brief Create an empty file.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param name The name of the file to create.
 * @return Index where the file entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_empty_file(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id, const char* name);

/**
 * @brief Create a directory.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_directory(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id, const char* name);

/**
 * @brief Create a hardlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param target_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_hardlink(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id, const char* name,
     struct CryptFS_Entry_ID target_entry_id);
/**
 * @brief Create a symlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param name Name of the symlink.
 * @param symlink The string corresponding to the symlink's path.
 * @return Index where the symlink entry is located in parent_directory on success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_symlink(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id, const char* name, const char *symlink);

#endif
