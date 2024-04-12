#include <stdio.h>
#include <stdlib.h>

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

int entry_truncate(unsigned char* aes_key, block_t directory_block, uint32_t directory_index, size_t new_size)
{
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