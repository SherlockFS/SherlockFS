#include "fuse_ps_info.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cryptfs.h"
#include "crypto.h"
#include "xalloc.h"

// ------------------- File descriptor management -------------------

static struct fs_file_info *fd_list = NULL;

struct fs_file_info *ffi_get_new_fd()
{
    // Find the highest file descriptor currently in use
    int max_fd = FD_MIN;
    for (struct fs_file_info *current = fd_list; current;
         current = current->next)
        if (current->fd > max_fd)
            max_fd = current->fd;

    if (max_fd == INT32_MAX)
    {
        errno = EMFILE;
        return NULL;
    }

    struct fs_file_info *old_fd_list_root = NULL;

    // Save the current fd_list if it exists
    if (fd_list)
    {
        // Old fd_list
        old_fd_list_root = xmalloc(1, sizeof(struct fs_file_info));
        old_fd_list_root->fd = fd_list->fd;
        old_fd_list_root->uid = fd_list->uid;
        old_fd_list_root->seek_offset = fd_list->seek_offset;
        old_fd_list_root->next = fd_list->next;
    }
    // Create a new fd_list
    else
    {
        fd_list = xmalloc(1, sizeof(struct fs_file_info));
    }

    // Push the new file descriptor
    fd_list->fd = max_fd + 1;
    fd_list->next = old_fd_list_root;

    return fd_list;
}

void ffi_release_fd(struct fs_file_info *file)
{
    if (!fd_list)
    {
        errno = EBADF;
        return;
    }

    errno = 0;

    // If the file descriptor to release is the only file descriptor
    if (!fd_list->next)
    {
        free(fd_list);
        fd_list = NULL;
        return;
    }

    for (struct fs_file_info *current = fd_list; current->next;
         current = current->next)
    {
        if (current->next->fd != file->fd)
            continue;

        struct fs_file_info *to_free = current->next;
        current->next = current->next->next;
        free(to_free);
        return;
    }

    // File descriptor not found
    errno = EBADF;
}

// ------------------- File system information management -------------------

struct fs_ps_info
{
    unsigned char master_key[AES_KEY_SIZE_BYTES]; // XORed AES master key
    unsigned char xor_key[AES_KEY_SIZE_BYTES]; // master key XOR key
    unsigned char decoded_key[AES_KEY_SIZE_BYTES]; // Decoded key (must be
                                                   // zeroed after use)
    block_t current_directory_block; // Current directory block number
};

static struct fs_ps_info info = {
    .master_key = { 0 },
    .xor_key = { 0 },
    .decoded_key = { 0 },
    .current_directory_block = ROOT_ENTRY_BLOCK,
};

void fpi_set_master_key(unsigned char *key)
{
    srand(time(NULL)); // Basic seed for random number generation, but
                       // acceptable for memory resilience

    for (int i = 0; i < AES_KEY_SIZE_BYTES; i++)
    {
        info.xor_key[i] = rand() % 0xFF; // Generate a random XOR key
        info.master_key[i] = key[i] ^ info.xor_key[i]; // Store the XOR'd key
    }

    // Erase the key from memory
    memset(key, 0, AES_KEY_SIZE_BYTES);
}

const unsigned char *fpi_get_master_key()
{
    for (int i = 0; i < AES_KEY_SIZE_BYTES; i++)
        info.decoded_key[i] = info.master_key[i]
            ^ info.xor_key[i]; // Decode the key before returning it

    return info.decoded_key; // ! Careful, the key must be zeroed after use
                             // using fpi_clear_decoded_key()
}

void fpi_clear_decoded_key()
{
    memset(info.decoded_key, 0, AES_KEY_SIZE_BYTES);
}

void fpi_set_current_directory_block(block_t block)
{
    info.current_directory_block = block;
}

block_t fpi_get_current_directory_block()
{
    return info.current_directory_block;
}
