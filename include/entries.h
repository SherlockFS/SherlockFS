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
 * @brief Given a string path, search for the entry unique identifier.
 *
 * @param path The path to the entry.
 * @return A entry unique identifier.
 */
struct CryptFS_Entry_ID search_entry(const char *path);

/**
 * @brief Search for the directory block where the index is pointing to.
 *
 * @example If index = 26, the function will update the numbers like so:
 * `directory_block` = FAT[directory] and `index` = 3.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry_id A entry unique identifier. Can be wrong (oversized `index`).
 * This function will update it with the correct values.
 * @return 0 when success, -1 otherwise.
 */
int goto_entry_in_directory(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID *entry_id);

/**
 * @brief Modify an cryptFS_entry size. Equivalent to Linux truncate syscall.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param new_size The new size for the entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_truncate(const unsigned char *aes_key,
                   struct CryptFS_Entry_ID entry_id, size_t new_size);

/**
 * @brief Write a buffer to an entry from a specific index.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param start_from The start index (in bytes) to begin writing.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer_from(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID file_entry_id,
                            size_t start_from, const void *buffer,
                            size_t count);

/**
 * @brief Write a buffer to an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param buffer The source buffer to write.
 * @param count The size of the source buffer.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_write_buffer(const unsigned char *aes_key,
                       struct CryptFS_Entry_ID file_entry_id,
                       const void *buffer, size_t count);

/**
 * @brief Read raw data from an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param file_entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param start_from The start index (in bytes) to begin reading.
 * @param buf The buffer to store the read data.
 * @param count The maximum size to read.
 * @return The actual size read on success, or BLOCK_ERROR otherwise.
 */
ssize_t entry_read_raw_data(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID file_entry_id,
                            size_t start_from, void *buf, size_t count);

/**
 * @brief Delete an entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param entry_index Index within the struct CryptFS_Directory pointed by
 * parent_dir_entry_id.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_delete(const unsigned char *aes_key,
                 struct CryptFS_Entry_ID parent_dir_entry_id,
                 uint32_t entry_index);

/**
 * @brief Create an empty file.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param name The name of the file to create.
 * @return Index where the file entry is located in parent_directory on success,
 * or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_empty_file(const unsigned char *aes_key,
                                 struct CryptFS_Entry_ID parent_dir_entry_id,
                                 const char *name);

/**
 * @brief Create a directory.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on
 * success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_directory(const unsigned char *aes_key,
                                struct CryptFS_Entry_ID parent_dir_entry_id,
                                const char *name);

/**
 * @brief Create a hardlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param target_entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param name The name of the directory to create.
 * @return Index where the directory entry is located in parent_directory on
 * success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_hardlink(const unsigned char *aes_key,
                               struct CryptFS_Entry_ID parent_dir_entry_id,
                               const char *name,
                               struct CryptFS_Entry_ID target_entry_id);
/**
 * @brief Create a symlink.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param name Name of the symlink.
 * @param symlink The string corresponding to the symlink's path.
 * @return Index where the symlink entry is located in parent_directory on
 * success, or BLOCK_ERROR otherwise.
 */
uint32_t entry_create_symlink(const unsigned char *aes_key,
                              struct CryptFS_Entry_ID parent_dir_entry_id,
                              const char *name, const char *symlink);

#endif
