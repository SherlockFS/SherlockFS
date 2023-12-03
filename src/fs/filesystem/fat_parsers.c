#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "fat.h"
#include "xalloc.h"

int64_t find_first_free_block(struct CryptFS_FAT *first_fat)
{
    if (!first_fat)
        return FAT_BLOCK_ERROR;

    for (int64_t i = 0; i < INT64_MAX; i++)
        switch (read_fat_offset(first_fat, (uint64_t)i))
        {
        case FAT_BLOCK_FREE:
            return i;
        case FAT_BLOCK_ERROR:
            return FAT_BLOCK_ERROR;
        default:
            break;
        }

    return FAT_BLOCK_ERROR;
}

int64_t create_fat(struct CryptFS_FAT *any_fat)
{
    // Find a free block in the disk.
    int64_t created_fat_block = find_first_free_block(any_fat);
    if (created_fat_block == FAT_BLOCK_ERROR)
        return FAT_BLOCK_ERROR;

    // Craft the new FAT block.
    struct CryptFS_FAT *created_fat = xaligned_calloc(
        sizeof(struct CryptFS_FAT), 1, CRYPTFS_BLOCK_SIZE_BYTES);

    created_fat->next_fat_table = FAT_BLOCK_END;

    // Save the first FAT (for `write_fat_offset()`)
    struct CryptFS_FAT *first_fat_cpy = memcpy(
        xaligned_alloc(sizeof(struct CryptFS_FAT), 1, CRYPTFS_BLOCK_SIZE_BYTES),
        any_fat, CRYPTFS_BLOCK_SIZE_BYTES);
    if (first_fat_cpy == NULL)
        return FAT_BLOCK_ERROR;

    // Find the last FAT in the FAT linked-list.
    struct CryptFS_FAT *last_fat = any_fat;
    while (last_fat->next_fat_table != (uint64_t)FAT_BLOCK_END)
        if (read_blocks(last_fat->next_fat_table, 1, last_fat) != 0)
            return FAT_BLOCK_ERROR;

    // Change the last FAT's next_fat_table to the new FAT block.
    last_fat->next_fat_table = created_fat_block;

    // Write the new FAT block to the disk.
    write_blocks(created_fat_block, 1, created_fat);

    // Mark the new FAT block as used.
    write_fat_offset(first_fat_cpy, created_fat_block, FAT_BLOCK_END);

    free(created_fat);
    free(first_fat_cpy);

    return created_fat_block;
}

int write_fat_offset(struct CryptFS_FAT *first_fat, uint64_t offset,
                     uint64_t value)
{
    if (!first_fat)
        return FAT_BLOCK_ERROR;

    uint64_t concerned_fat = offset / NB_FAT_ENTRIES_PER_BLOCK;

    // Parsing the FAT linked-list
    uint64_t current_fat_block = FIRST_FAT_BLOCK;
    for (uint64_t i = 0; i < concerned_fat; i++)
    {
        current_fat_block = first_fat->next_fat_table;
        if (read_blocks(first_fat->next_fat_table, 1, first_fat) == -1)
        {
            int64_t new_fat_block = create_fat(first_fat);
            if (new_fat_block == FAT_BLOCK_ERROR)
                return FAT_BLOCK_ERROR;
            first_fat->next_fat_table = new_fat_block;
        }
    }

    struct CryptFS_FAT_Entry *entry =
        &first_fat->entries[offset % NB_FAT_ENTRIES_PER_BLOCK];

    entry->next_block = value;

    write_blocks(current_fat_block, 1, first_fat);

    // Update first FAT if concerned
    if (concerned_fat == 0 && read_blocks(FIRST_FAT_BLOCK, 1, first_fat) == -1)
        return FAT_BLOCK_ERROR;

    return 0;
}

int64_t read_fat_offset(struct CryptFS_FAT *first_fat, uint64_t offset)
{
    if (!first_fat)
        return FAT_BLOCK_ERROR;

    uint64_t concerned_fat = offset / NB_FAT_ENTRIES_PER_BLOCK;

    struct CryptFS_FAT *tmp_fat = xaligned_calloc(sizeof(struct CryptFS_FAT), 1,
                                                  CRYPTFS_BLOCK_SIZE_BYTES);
    memcpy(tmp_fat, first_fat, CRYPTFS_BLOCK_SIZE_BYTES);

    // Parsing the FAT linked-list
    for (uint64_t i = 0; i < concerned_fat; i++)
        if (tmp_fat->next_fat_table == (uint64_t)FAT_BLOCK_END
            || read_blocks(tmp_fat->next_fat_table, 1, tmp_fat) == -1)
        {
            free(tmp_fat);
            return FAT_BLOCK_ERROR;
        }

    // Update first FAT if concerned
    if (concerned_fat == 0 && read_blocks(FIRST_FAT_BLOCK, 1, first_fat) == -1)
    {
        free(tmp_fat);
        return FAT_BLOCK_ERROR;
    }

    uint32_t entry_next_block =
        tmp_fat->entries[offset % NB_FAT_ENTRIES_PER_BLOCK].next_block;

    free(tmp_fat);
    return entry_next_block;
}
