#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entries.h"
#include "block.h"
#include "fat.h"
#include "cryptfs.h"
#include "xalloc.h"

int blocks_needed_for_file(size_t size)
// Minimal necessary blocks needed to stock /size/ bytes
{
    int result = size / CRYPTFS_BLOCK_SIZE_BYTES ;
    if (size % CRYPTFS_BLOCK_SIZE_BYTES != (float) 0) {
        return result + 1; 
    } else {
        return result;
    }
}

int blocks_needed_for_dir(size_t size)
// Minimal necessary blocks needed to stock /size/ entries in a directory
{
    int result = size * sizeof(struct CryptFS_Entry) / CRYPTFS_BLOCK_SIZE_BYTES ;
    if (size * sizeof(struct CryptFS_Entry) % CRYPTFS_BLOCK_SIZE_BYTES != (float) 0) {
        return result + 1;
    } else {
        return result;
    }
}

// Return 0 on success, -1 if error
int create_new_blocks(unsigned char* aes_key, size_t new_blocks_needed, size_t actual_blocks_used, struct CryptFS_Entry entry)
{
    // Parcour the FAT to reach last block of this directory
    uint64_t end_block = entry.start_block;
    while ((int) read_fat_offset(aes_key, end_block) != BLOCK_END)
    {
        end_block = (uint64_t) read_fat_offset(aes_key, end_block);
    }
    while (actual_blocks_used < new_blocks_needed)
    {
        block_t new_end = find_first_free_block_safe(aes_key);
        if (new_end == (size_t) BLOCK_ERROR)
            return -1;
        if (write_fat_offset(aes_key, end_block, new_end))
            return -1;
        actual_blocks_used += 1;
        end_block = new_end;
        if (write_fat_offset(aes_key, end_block, BLOCK_END))
            return -1;
    }
    // Put BLOCK_END in the FAT
    if (write_fat_offset(aes_key, end_block, BLOCK_END))
        return -1;
    return 0;
}

// Return 0 on success, -1 if error
int free_blocks(unsigned char* aes_key, size_t new_blocks_needed, struct CryptFS_Entry* entry)
{
    block_t end_block = entry->start_block;
    block_t free_block;
    
    if (new_blocks_needed == 0)
    {
        // Free all blocks till BLOCK_END
        free_block = end_block;
        while ((int)read_fat_offset(aes_key, free_block) != BLOCK_END)
        {
            end_block = read_fat_offset(aes_key, free_block);
            if (end_block == (size_t) BLOCK_ERROR)
                return -1;
            if (write_fat_offset(aes_key, free_block, BLOCK_FREE))
                return -1;
            free_block = end_block;
        }
        // Original BLOCK_END becomes BLOCK_FREE
        if (write_fat_offset(aes_key, free_block, BLOCK_FREE))
            return -1;
        // Update entry.start_entry to 0
        entry->start_block = 0;
    }
    else
    {
        // > 1 Because if new_blocks_needed != 0, it is inevitably >=1 
        while (new_blocks_needed > 1)
        {
            end_block = (uint64_t) read_fat_offset(aes_key, end_block);
            new_blocks_needed--;
        }
        // end_block is the new BLOCK_END of the entry
        free_block = read_fat_offset(aes_key, end_block);
        if (write_fat_offset(aes_key, end_block, BLOCK_END))
            return -1;
        // Free all other blocks till original BLOCK_END
        while ((int)read_fat_offset(aes_key, free_block) != BLOCK_END)
        {
            end_block = read_fat_offset(aes_key, free_block);
            if (write_fat_offset(aes_key, free_block, BLOCK_FREE))
                return -1;
            free_block = end_block;
        }
        // Original BLOCK_END becomes BLOCK_FREE
        if (write_fat_offset(aes_key, free_block, BLOCK_FREE))
            return -1;
    }
    return 0;
}

// Move to the correcto directory block and update the index for this block
int search_entry_in_directory(unsigned char* aes_key, block_t* directory_block, uint32_t* index)
{
    if (*index > NB_ENTRIES_PER_BLOCK)
    {
        int count = *index / NB_ENTRIES_PER_BLOCK;
        *index = *index % NB_ENTRIES_PER_BLOCK;
        while (count > 1 && read_fat_offset(aes_key, *directory_block))
        {
            *directory_block = read_fat_offset(aes_key, *directory_block);
            count--;
        }
        if (count > 1)
            return -1;
    }
    return 0;
    
    
    // while (*index > NB_ENTRIES_PER_BLOCK && read_fat_offset(aes_key, *directory_block))
    // {
    //     *index -= NB_ENTRIES_PER_BLOCK;
    //     *directory_block = read_fat_offset(aes_key, *directory_block);
    // }
    // if (*index > NB_ENTRIES_PER_BLOCK)
    // {
    //     return -1;
    // }
    // return 0;
    
}

int entry_truncate(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t new_size)
{
    if (search_entry_in_directory(aes_key, &directory_block, &directory_index))
        return BLOCK_ERROR;

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, directory_block, 1, dir) == BLOCK_ERROR)
        goto err_truncate_entry;
    
    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[directory_index];

    // Check if new_size is different
    if (new_size != entry.size)
    {
        // If entry is empty, initialize start_block
        if (entry.start_block == 0)
        {
            block_t start = find_first_free_block_safe(aes_key);
            if (start == (size_t) BLOCK_ERROR)
                goto err_truncate_entry;
            entry.start_block = start;
            if (write_fat_offset(aes_key, start, BLOCK_END))
                goto err_truncate_entry;
            
        }
        size_t actual_blocks_used; 
        size_t new_blocks_needed;
        // Check the entry type
        if (entry.type == ENTRY_TYPE_DIRECTORY)
        {
            new_blocks_needed = blocks_needed_for_dir(new_size);
            actual_blocks_used = blocks_needed_for_dir(entry.size);  
        }
        else
        {
            new_blocks_needed = blocks_needed_for_file(new_size);
            actual_blocks_used = blocks_needed_for_file(entry.size);
        }

        if (new_blocks_needed > actual_blocks_used)
        {
            if (create_new_blocks(aes_key, new_blocks_needed, actual_blocks_used, entry))
                goto err_truncate_entry;
        }
        else if (new_blocks_needed < actual_blocks_used)
        {
            if (free_blocks(aes_key, new_blocks_needed, &entry))
                goto err_truncate_entry;
        }

        // If the size changed but new_blocks_needed is the same
        // only change the entry.size

        // Update entry size in the header and write back in directory block
        entry.size = new_size;
        dir->entries[directory_index] = entry;
        if (write_blocks_with_encryption(aes_key, directory_block, 1, dir))
            goto err_truncate_entry;
    }
    // Do nothing if new_size is equal to entry.size
    free(dir);
    return 0;

    err_truncate_entry:
        free(dir);
        return BLOCK_ERROR;
}

int entry_write_buffer_from(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t start_from, void* buffer, size_t count)
{
    // Find the real block and index
    block_t dir_block_real = directory_block;
    uint32_t dir_index_real = directory_index;
    if (search_entry_in_directory(aes_key, &dir_block_real, &dir_index_real))
        return BLOCK_ERROR;
    

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    

    if (read_blocks_with_decryption(aes_key, dir_block_real, 1, dir) == BLOCK_ERROR)
        goto err_write_buffer_entry;
    
    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[dir_index_real];

    // Can't write buffer in a directory
    if (entry.type == ENTRY_TYPE_DIRECTORY)
        goto err_write_buffer_entry;

    size_t sum_writing = start_from + count;
    if (sum_writing > entry.size)
        entry_truncate(aes_key, directory_block, directory_index, sum_writing);

    block_t s_block = entry.start_block;
    int count_blocks = start_from / CRYPTFS_BLOCK_SIZE_BYTES; // Number of the block to start writing
    // int r_start = start_from % CRYPTFS_BLOCK_SIZE_BYTES; // Relative starting index to the start writing block
    while (count_blocks > 1 && read_fat_offset(aes_key, s_block))
    {
        s_block = read_fat_offset(aes_key, s_block);
        count_blocks--;
    }
    if (count_blocks > 1)
        goto err_write_buffer_entry;

    // Loop to write Buffer in buffer_blocks
    
    char *block_buffer = 
        xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    
    // If block is empty, initialize buffer to avoid reading in STACK
    if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
        memset(block_buffer, '\0', CRYPTFS_BLOCK_SIZE_BYTES);

    size_t modulo_index = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (start_from + modulo_index >= CRYPTFS_BLOCK_SIZE_BYTES) 
        {
            // Write back the block_buffer
            if (write_blocks_with_encryption(aes_key, s_block, 1, block_buffer))
                goto err_write_buffer_entry_2;
            s_block = read_fat_offset(aes_key, s_block);
            if (s_block == (block_t) BLOCK_ERROR)
                goto err_write_buffer_entry_2;
            start_from = 0;
            modulo_index = 0;
            if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
                memset(block_buffer, '\0', CRYPTFS_BLOCK_SIZE_BYTES);
        }

        block_buffer[start_from + modulo_index] = ((char*)buffer)[i];
        modulo_index++;
    }

    // Write back the last block_buffer
    if (write_blocks_with_encryption(aes_key, s_block, 1, block_buffer))
        goto err_write_buffer_entry_2;

    free(block_buffer);
    free(dir);  
    return 0;

    err_write_buffer_entry:
        free(dir);
        return BLOCK_ERROR;

    err_write_buffer_entry_2:
        free(block_buffer);
        free(dir);
        return BLOCK_ERROR;
}

int entry_write_buffer(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, void* buffer, size_t count)
{
    return entry_write_buffer_from(aes_key, directory_block, directory_index, 0, buffer, count);
}

ssize_t entry_read_raw_data(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t start_from, void* buf, size_t count)
{
    ssize_t result = 0;

    // Find the real block and index
    if (search_entry_in_directory(aes_key, &directory_block, &directory_index))
        return BLOCK_ERROR;

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, directory_block, 1, dir) == BLOCK_ERROR)
        goto err_read_entry;
    
    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[directory_index];

    // Check if the offset to read is correct
    if (entry.size < start_from + count)
        goto err_read_entry;
    
    sblock_t s_block = entry.start_block;
    while (start_from >= CRYPTFS_BLOCK_SIZE_BYTES)
    {
        s_block = read_fat_offset(aes_key, s_block);
        if (s_block)
            goto err_read_entry;
        start_from -= CRYPTFS_BLOCK_SIZE_BYTES;
    }

    // Loop to read buffer_blocks to buffer

    // allocate block_buffer to read block    
    char *block_buffer = 
        xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    
    // If block is empty, return BLOCK_ERROR
    if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
        goto err_read_entry;

    size_t modulo_index = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (start_from + modulo_index >= CRYPTFS_BLOCK_SIZE_BYTES) 
        {
            s_block = read_fat_offset(aes_key, s_block);
            if (s_block == (sblock_t) BLOCK_ERROR)
                goto err_read_entry;
            start_from = 0;
            modulo_index = 0;
            if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
                goto err_read_entry;
        }
        ((char*)buf)[i] = block_buffer[start_from + modulo_index];
        modulo_index++;
        result++;
    }
    
    free(dir);
    free(block_buffer);
    return result;

    err_read_entry:
        free(dir);
        free(block_buffer);
        return BLOCK_ERROR;
}