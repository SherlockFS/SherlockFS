#include "block.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cryptfs.h"
#include "crypto.h"
#include "xalloc.h"

const char *DEVICE_PATH = NULL;
uint32_t BLOCK_SIZE = 0;

void set_device_path(const char *path)
{
    assert(path != NULL);
    DEVICE_PATH = path;
}

const char *get_device_path()
{
    assert(DEVICE_PATH != NULL);
    return DEVICE_PATH;
}

void set_block_size(const uint32_t size)
{
    assert(size >= CRYPTFS_BLOCK_SIZE_BYTES);
    BLOCK_SIZE = size;
}

uint32_t get_block_size()
{
    assert(BLOCK_SIZE >= CRYPTFS_BLOCK_SIZE_BYTES);
    return BLOCK_SIZE;
}

int read_blocks(block_t start_block, size_t nb_blocks, void *buffer)
{
    assert(DEVICE_PATH != NULL);
    assert(BLOCK_SIZE != 0);

    if (nb_blocks == 0)
        return 0;
    if (!buffer)
        return -1;

    FILE *file = fopen(DEVICE_PATH, "r");
    if (!file)
        return -1;

    if (fseek(file, start_block * BLOCK_SIZE, SEEK_SET) != 0)
        return -1;

    size_t read = 0;
    while (read < nb_blocks)
    {
        size_t n = fread(buffer + read * get_block_size(), get_block_size(),
                         nb_blocks - read, file);
        if (n == 0)
            return -1;
        read += n;
    }

    if (fclose(file) != 0)
        return -1;

    return 0;
}

int write_blocks(block_t start_block, size_t nb_blocks, void *buffer)
{
    assert(DEVICE_PATH != NULL);
    assert(BLOCK_SIZE != 0);

    if (nb_blocks == 0)
        return 0;
    if (buffer == NULL)
        return -1;

    FILE *file = fopen(DEVICE_PATH, "r+");
    if (file == NULL)
        return -1;

    if (fseek(file, start_block * get_block_size(), SEEK_SET) == -1)
        return -1;

    size_t written = 0;
    while (written < nb_blocks)
    {
        size_t n = fwrite(buffer + written * get_block_size(), get_block_size(),
                          nb_blocks - written, file);
        if (n == 0)
            return -1;
        written += n;
    }

    if (fclose(file) == -1)
        return -1;

    return 0;
}

int read_blocks_with_decryption(unsigned char *aes_key, block_t start_block,
                                size_t nb_blocks, void *buffer)
{
    unsigned char *encrypted_buffer = xmalloc(nb_blocks, get_block_size());
    int read_blocks_res = read_blocks(start_block, nb_blocks, encrypted_buffer);

    if (read_blocks_res == -1)
    {
        free(encrypted_buffer);
        return -1;
    }

    size_t useless_size = 0;
    unsigned char *decrypted_buffer = aes_decrypt_data(
        aes_key, encrypted_buffer, nb_blocks * get_block_size(), &useless_size);

    if (decrypted_buffer == NULL)
    {
        free(encrypted_buffer);
        free(decrypted_buffer);
        return -1;
    }

    memcpy(buffer, decrypted_buffer, nb_blocks * get_block_size());
    free(encrypted_buffer);
    free(decrypted_buffer);
    return 0;
}

int write_blocks_with_encryption(unsigned char *aes_key, size_t start_block,
                                 size_t nb_blocks, void *buffer)
{
    size_t useless_size = 0;
    unsigned char *encrypted_buffer = aes_encrypt_data(
        aes_key, buffer, nb_blocks * get_block_size(), &useless_size);
    if (encrypted_buffer == NULL)
        return -1;
    int write_blocks_res =
        write_blocks(start_block, nb_blocks, encrypted_buffer);
    free(encrypted_buffer);
    return write_blocks_res;
}
