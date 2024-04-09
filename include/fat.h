#ifndef FAT_H
#define FAT_H

#include "cryptfs.h"

/**
 * @brief Find the first free block in the FAT table.
 *
 * @param aes_key The AES key to use for in place decryption of the FAT tables.
 *
 * @return sblock_t The index of the first free block,
 * or BLOCK_ERROR first_fat is NULL or if an error occured. In case of out
 * of range, a negative value is returned (the absolute value is the index of
 * the first out of range [and also available] block).
 */
sblock_t find_first_free_block(const unsigned char *aes_key);

/**
 * @brief Find the first safe free block in the FAT table.
 *
 * @param aes_key The AES key to use for in place decryption of the FAT tables.
 *
 * @return sblock_t The index of the first free block, the difference with 
 * "find_first_free_block" is that it only return a positive block index as it 
 * initialize another FAT in case of out of range.
 */
block_t find_first_free_block_safe(const unsigned char *aes_key);

/**
 * @brief Append a FAT table to the FAT linked-list.
 *
 * @param aes_key The AES key to use for in place decryption of the FAT tables.
 *
 * @note The function still works if you pass any FAT table as first_fat
 * (not only the first one).
 *
 * @return sblock_t The block where the new FAT is stored,
 * or BLOCK_ERROR if an error occurs.
 */
sblock_t create_fat(const unsigned char *aes_key);

/**
 * @brief Write `value` to the FAT table at `offset` index.
 *
 * @param aes_key The AES key to use for in place decryption of the FAT tables.
 * @param offset The index of the FAT table to write to.
 * @param value The value to write.
 * @return int 0 on success, BLOCK_ERROR on error. BLOCK_FAT_OOB in case of out
 * of range.
 */
int write_fat_offset(const unsigned char *aes_key, uint64_t offset,
                     uint64_t value);

/**
 * @brief Read the value at `offset` index in the FAT table.
 *
 * @param aes_key The AES key to use for in place decryption of the FAT tables.
 * @param offset The index of the FAT table to read from.
 * @return uint32_t The value at `offset` index in the FAT table. BLOCK_ERROR
 * on error. BLOCK_FAT_OOB in case of out of range.
 */
uint32_t read_fat_offset(const unsigned char *aes_key, uint64_t offset);

#endif /* FAT_H */
