#include "block.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "cryptfs.h"
#include "crypto.h"
#include "print.h"
#include "xalloc.h"

const char *DEVICE_PATH = NULL;

void set_device_path(const char *path)
{
    assert(path != NULL);
    DEVICE_PATH = path;

    // Create file (if not created)
    FILE *tmp_file = fopen(path, "r+");
    if (!tmp_file)
        error_exit("Impossible to open device file '%s': %s\n", EXIT_FAILURE,
                   path, strerror(errno));

    // Check file size
    fseek(tmp_file, 0, SEEK_END);
    size_t file_size = ftell(tmp_file);
    if (file_size < sizeof(struct CryptFS))
        error_exit("The file '%s' is too small to be a SherlockFS device\n",
                   EXIT_FAILURE, path);

    fseek(tmp_file, 0, SEEK_SET);
    fclose(tmp_file);
}

const char *get_device_path()
{
    assert(DEVICE_PATH != NULL);
    return DEVICE_PATH;
}

int read_blocks(block_t start_block, size_t nb_blocks, void *buffer)
{
    assert(DEVICE_PATH != NULL);

    if (nb_blocks == 0)
        return 0;
    if (!buffer)
        return BLOCK_ERROR;

    FILE *file = fopen(DEVICE_PATH, "r+");
    if (!file)
    {
        error_exit("fopen '%s' failed: %s\n", EXIT_FAILURE, DEVICE_PATH,
                   strerror(errno));
        return BLOCK_ERROR;
    }

    if (fseek(file, start_block * CRYPTFS_BLOCK_SIZE_BYTES, SEEK_SET) != 0)
    {
        error_exit("fseek '%s' failed: %s\n", EXIT_FAILURE, DEVICE_PATH,
                   strerror(errno));
        return BLOCK_ERROR;
    }

    size_t read = 0;
    while (read < nb_blocks)
    {
        size_t n = fread(buffer + read * CRYPTFS_BLOCK_SIZE_BYTES,
                         CRYPTFS_BLOCK_SIZE_BYTES, nb_blocks - read, file);
        if (n == 0)
            return BLOCK_ERROR;

        read += n;
    }

    if (fclose(file) != 0)
        return BLOCK_ERROR;

    return 0;
}

int write_blocks(block_t start_block, size_t nb_blocks, const void *buffer)
{
    assert(DEVICE_PATH != NULL);

    if (nb_blocks == 0)
        return 0;
    if (buffer == NULL)
        return BLOCK_ERROR;

    FILE *file = fopen(DEVICE_PATH, "r+");
    if (!file)
    {
        error_exit("fopen '%s' failed: %s\n", EXIT_FAILURE, DEVICE_PATH,
                   strerror(errno));
        return BLOCK_ERROR;
    }

    if (fseek(file, start_block * CRYPTFS_BLOCK_SIZE_BYTES, SEEK_SET) == -1)
    {
        error_exit("fseek '%s' failed: %s\n", EXIT_FAILURE, DEVICE_PATH,
                   strerror(errno));
        return BLOCK_ERROR;
    }

    size_t written = 0;
    while (written < nb_blocks)
    {
        size_t n = fwrite(buffer + written * CRYPTFS_BLOCK_SIZE_BYTES,
                          CRYPTFS_BLOCK_SIZE_BYTES, nb_blocks - written, file);
        if (n == 0)
            return BLOCK_ERROR;

        written += n;
    }

    if (fclose(file) == -1)
        return BLOCK_ERROR;

    return 0;
}

int read_blocks_with_decryption(const unsigned char *aes_key,
                                block_t start_block, size_t nb_blocks,
                                void *buffer)
{
    unsigned char *encrypted_buffer =
        xmalloc(nb_blocks, CRYPTFS_BLOCK_SIZE_BYTES);
    int read_blocks_res = read_blocks(start_block, nb_blocks, encrypted_buffer);

    if (read_blocks_res < 0)
    {
        free(encrypted_buffer);
        return read_blocks_res;
    }

    size_t useless_size = 0;
    unsigned char *decrypted_buffer =
        aes_decrypt_data(aes_key, encrypted_buffer,
                         nb_blocks * CRYPTFS_BLOCK_SIZE_BYTES, &useless_size);

    if (decrypted_buffer == NULL)
    {
        free(encrypted_buffer);
        free(decrypted_buffer);
        return -1;
    }

    memcpy(buffer, decrypted_buffer, nb_blocks * CRYPTFS_BLOCK_SIZE_BYTES);
    free(encrypted_buffer);
    free(decrypted_buffer);
    return 0;
}

int write_blocks_with_encryption(const unsigned char *aes_key,
                                 block_t start_block, size_t nb_blocks,
                                 const void *buffer)
{
    size_t useless_size = 0;
    unsigned char *encrypted_buffer = aes_encrypt_data(
        aes_key, buffer, nb_blocks * CRYPTFS_BLOCK_SIZE_BYTES, &useless_size);
    if (encrypted_buffer == NULL)
        return -1;
    int write_blocks_res =
        write_blocks(start_block, nb_blocks, encrypted_buffer);
    free(encrypted_buffer);
    return write_blocks_res;
}
