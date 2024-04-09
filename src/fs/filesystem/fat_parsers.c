#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "fat.h"
#include "print.h"
#include "xalloc.h"

sblock_t find_first_free_block(const unsigned char *aes_key)
{
    for (int64_t i = 0; i < INT64_MAX; i++)
        switch (read_fat_offset(aes_key, (uint64_t)i))
        {
        case BLOCK_FREE:
            return i;
        case BLOCK_FAT_OOB:
            return -i;
        case BLOCK_ERROR:
            return BLOCK_ERROR;
        default:
            break;
        }

    return BLOCK_ERROR;
}

block_t find_first_free_block_safe(const unsigned char *aes_key)
{
    sblock_t index = find_first_free_block(aes_key);
    if (index == BLOCK_ERROR)
        return BLOCK_ERROR;
    if (index < 0)
    {
        if (create_fat(aes_key) == BLOCK_ERROR)
            return BLOCK_ERROR;
        return -index + 1;
    }
    
    return index;
}


sblock_t create_fat(const unsigned char *aes_key)
{
    // Header (which contains last_fat_block index)
    struct CryptFS_Header *header = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Header));
    // Last already in place FAT (at index last_fat_block)
    struct CryptFS_FAT *last_fat =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_FAT));
    // New created FAT
    struct CryptFS_FAT *new_fat =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_FAT));

    // Loading last in place FAT into memory
    if (read_blocks(HEADER_BLOCK, 1, header) == BLOCK_ERROR)
        goto err_create_fat;
    if (read_blocks_with_decryption(aes_key, header->last_fat_block, 1,
                                    last_fat)
        == BLOCK_ERROR)
        goto err_create_fat;

    // Finding an available block to store the new FAT
    int64_t new_fat_block = find_first_free_block(aes_key);
    if (new_fat_block == BLOCK_ERROR)
        return BLOCK_ERROR;

    if (new_fat_block < 0) // Out of FAT at index -new_fat_block
    {
        // The new FAT is just after the last handled index in current FATs
        uint64_t new_oob_fat_block = (uint64_t)-new_fat_block;

        // Creating new FAT at block `new_oob_fat_block`
        new_fat->next_fat_table = BLOCK_END;
        new_fat->entries[0].next_block = BLOCK_END;
        if (write_blocks_with_encryption(aes_key, new_oob_fat_block, 1, new_fat)
            == BLOCK_ERROR)
            goto err_create_fat;

        // Updating the last FAT to point to the new OOB FAT
        last_fat->next_fat_table = new_oob_fat_block;
        if (write_blocks_with_encryption(aes_key, header->last_fat_block, 1,
                                         last_fat)
            == BLOCK_ERROR)
            goto err_create_fat;

        // Updating the header to point to the new OOB FAT
        header->last_fat_block = new_oob_fat_block;
        if (write_blocks(HEADER_BLOCK, 1, header) == BLOCK_ERROR)
            goto err_create_fat;

        free(last_fat);
        free(new_fat);
        free(header);
        return new_oob_fat_block;
    }
    else
    {
        // Craft the new FAT block.
        new_fat->next_fat_table = BLOCK_END;

        // Change the last FAT's next_fat_table to the new FAT block.
        last_fat->next_fat_table = new_fat_block;

        // Write the new FAT block to the disk.
        if (write_blocks_with_encryption(aes_key, new_fat_block, 1, new_fat))
            goto err_create_fat;

        // Mark the new FAT block as used.
        if (write_fat_offset(aes_key, new_fat_block, BLOCK_END))
            goto err_create_fat;

        // Updating the header to point to the new OOB FAT
        header->last_fat_block = new_fat_block;
        if (write_blocks(HEADER_BLOCK, 1, header) == BLOCK_ERROR)
            goto err_create_fat;

        free(last_fat);
        free(new_fat);
        free(header);
        return new_fat_block;
    }

err_create_fat:
    free(last_fat);
    free(new_fat);
    free(header);
    return BLOCK_ERROR;
}

int write_fat_offset(const unsigned char *aes_key, uint64_t offset,
                     uint64_t value)
{
    // Find a free block in the disk.
    struct CryptFS_FAT first_fat = { 0 };
    if (read_blocks_with_decryption(aes_key, FIRST_FAT_BLOCK, 1, &first_fat))
        return BLOCK_ERROR;

    uint64_t concerned_fat = offset / NB_FAT_ENTRIES_PER_BLOCK;

    // Parsing the FAT linked-list
    uint64_t current_fat_block = FIRST_FAT_BLOCK;
    for (uint64_t i = 0; i < concerned_fat; i++)
    {
        current_fat_block = first_fat.next_fat_table;
        if (first_fat.next_fat_table == (uint64_t)BLOCK_END)
            return BLOCK_FAT_OOB;
        if (read_blocks_with_decryption(aes_key, first_fat.next_fat_table, 1,
                                        &first_fat)
            == BLOCK_ERROR)
            return BLOCK_ERROR;
    }

    first_fat.entries[offset % NB_FAT_ENTRIES_PER_BLOCK].next_block = value;

    if (write_blocks_with_encryption(aes_key, current_fat_block, 1, &first_fat))
        return BLOCK_ERROR;

    return 0;
}

uint32_t read_fat_offset(const unsigned char *aes_key, uint64_t offset)
{
    // Find a free block in the disk.
    struct CryptFS_FAT tmp_fat = { 0 };
    if (read_blocks_with_decryption(aes_key, FIRST_FAT_BLOCK, 1, &tmp_fat))
        return BLOCK_ERROR;

    uint64_t concerned_fat = offset / NB_FAT_ENTRIES_PER_BLOCK;

    // Parsing the FAT linked-list
    for (uint64_t i = 0; i < concerned_fat; i++)
    {
        if (tmp_fat.next_fat_table == (uint64_t)BLOCK_END)
            return BLOCK_FAT_OOB;

        if (read_blocks_with_decryption(aes_key, tmp_fat.next_fat_table, 1,
                                        &tmp_fat)
            == -1)
            return BLOCK_ERROR;
    }

    return tmp_fat.entries[offset % NB_FAT_ENTRIES_PER_BLOCK].next_block;
}
