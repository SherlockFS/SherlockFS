#ifndef ENTRIES_H
#define ENTRIES_H

#include "cryptfs.h"


/**
 * @brief Return the number of blocks needed for size octet.
 *
 * @param size The new size for the entry.
 * @return Number of blocks.
 */
int blocks_needed_for_file(size_t size);

/**
 * @brief Return the number of blocks needed for size entries
 *
 * @param size The new size for the entry.
 * @return Number of blocks.
 */
int blocks_needed_for_dir(size_t size);

/**
 * @brief Modify an cryptFS_entry size.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry_block The block index to struct CryptFS_Entry.
 * @param new_size The new size for the entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
int entry_truncate(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t new_size);


#endif
