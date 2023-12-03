#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef size_t block_t;

/**
 * @brief Set the device path global variable.
 *
 * @param path The path of the device.
 */
void set_device_path(const char *path);

/**
 * @brief Get the device path global variable.
 *
 * @return The device path global variable.
 */
const char *get_device_path();

/**
 * @brief Read blocks from the device.
 *
 * @param start_block The first block to read.
 * @param nb_blocks The number of blocks to read.
 * @param buffer The buffer to fill with the blocks.
 * (Must be allocated with at least CRYPTFS_BLOCK_SIZE_BYTES * nb_blocks bytes)
 *
 * @return 0 on success, -1 on error.
 */
int read_blocks(block_t start_block, size_t nb_blocks, void *buffer);

/**
 * @brief Write blocks to the device.
 *
 * @param start_block The first block to write.
 * @param nb_blocks The number of blocks to write.
 * @param buffer The buffer containing the blocks.
 *
 * @return 0 on success, -1 on error.
 */
int write_blocks(block_t start_block, size_t nb_blocks, void *buffer);

/**
 * @brief Read a block from the device and decrypt it.
 *
 * @param aes_key The AES key to use for decryption.
 * @param start_block The first block to read.
 * @param nb_blocks The number of blocks to read.
 * @param buffer The buffer to fill with the blocks.
 * @return int 0 on success, -1 on error.
 */
int read_blocks_with_decryption(unsigned char *aes_key, block_t start_block,
                                size_t nb_blocks, void *buffer);

/**
 * @brief Write a block to the device and encrypt it.
 *
 * @param aes_key The AES key to use for encryption.
 * @param start_block The first block to write.
 * @param nb_blocks The number of blocks to write.
 * @param buffer The buffer containing the blocks.
 * @return int 0 on success, -1 on error.
 */
int write_blocks_with_encryption(unsigned char *aes_key, block_t start_block,
                                 size_t nb_blocks, void *buffer);

#endif /* BLOCK_H */
