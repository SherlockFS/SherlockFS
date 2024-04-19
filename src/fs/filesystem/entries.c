#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "entries.h"
#include "block.h"
#include "fat.h"
#include "cryptfs.h"
#include "xalloc.h"
#include "ascii.h"


int __blocks_needed_for_file(size_t size)
{
    int result = size / CRYPTFS_BLOCK_SIZE_BYTES ;
    if (size % CRYPTFS_BLOCK_SIZE_BYTES != (float) 0) {
        return result + 1; 
    } else {
        return result;
    }
}

int __blocks_needed_for_dir(size_t size)
{
    int result = size / NB_ENTRIES_PER_BLOCK ;
    if (size % NB_ENTRIES_PER_BLOCK != (float) 0) {
        return result + 1;
    } else {
        return result;
    }
}

/**
 * @brief Allocate new blocks to an entry when truncate is needed.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param new_blocks_needed Number of blocks to reach.
 * @param actual_blocks_used Number of blocks already allocated to the entry.
 * @param entry Actual CryptFS_Entry
 * @param entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @return 0 when success, -1 otherwise.
 */
static int __create_new_blocks(unsigned char* aes_key, size_t new_blocks_needed,
     size_t actual_blocks_used, struct CryptFS_Entry* entry, struct CryptFS_Entry_ID entry_id)
{
    struct CryptFS_Directory *init_dir =
            xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));
    init_dir->current_directory_entry = entry_id;
    // If entry is empty, initialize start_block
    if (entry->start_block == 0)
    {
        block_t start = find_first_free_block_safe(aes_key);
        if (start == (size_t) BLOCK_ERROR)
            goto err_create_new_block;
        entry->start_block = start;
        if (write_fat_offset(aes_key, start, BLOCK_END))
            goto err_create_new_block;
        if (entry->type == ENTRY_TYPE_DIRECTORY)
            write_blocks_with_encryption(aes_key, start, 1, init_dir);
        actual_blocks_used++;
    }
    // Parcour the FAT to reach last block of this directory
    uint64_t end_block = entry->start_block;
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
        if (entry->type == ENTRY_TYPE_DIRECTORY)
            write_blocks_with_encryption(aes_key, end_block, 1, init_dir);
    }
    free(init_dir);
    return 0;

    err_create_new_block:
        free(init_dir);
        return BLOCK_ERROR;
}

/**
 * @brief Free blocks to an entry when truncate is needed.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param new_blocks_needed Number of blocks to reach.
 * @param entry Pointer to a CryptFS_Entry.
 * @return 0 when success, -1 otherwise.
 */
static int __free_blocks(unsigned char* aes_key, size_t new_blocks_needed, struct CryptFS_Entry* entry)
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

/**
 * @brief Search for the directory block where the index is pointing to.
 * @example If index = 26, the function will update the numbers like so: 
 * directory_block = FAT[directory] and index = 3.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @return 0 when success, -1 otherwise.
 */
static int __search_entry_in_directory(unsigned char* aes_key, struct CryptFS_Entry_ID* entry_id)
{
    if (entry_id->directory_index > NB_ENTRIES_PER_BLOCK)
    {
        int count = entry_id->directory_index / NB_ENTRIES_PER_BLOCK;
        entry_id->directory_index = entry_id->directory_index % NB_ENTRIES_PER_BLOCK;
        while (count > 1 && read_fat_offset(aes_key, entry_id->directory_block))
        {
            entry_id->directory_block = read_fat_offset(aes_key, entry_id->directory_block);
            count--;
        }
        if (count > 1)
            return -1;
    }
    return 0; 
}

/**
 * @brief Loop to truncate entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer to CryptFS_Entry.
 * @param entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param new_size Size to truncate the entry with.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_truncate_treatment(unsigned char* aes_key, struct CryptFS_Entry* entry,
     struct CryptFS_Entry_ID entry_id, size_t new_size)
{
    // Check if new_size is different
    if (new_size != entry->size)
    {
        size_t actual_blocks_used; 
        size_t new_blocks_needed;
        // Check the entry type
        if (entry->type == ENTRY_TYPE_DIRECTORY)
        {
            new_blocks_needed = __blocks_needed_for_dir(new_size);
            actual_blocks_used = __blocks_needed_for_dir(entry->size);  
        }
        else
        {
            new_blocks_needed = __blocks_needed_for_file(new_size);
            actual_blocks_used = __blocks_needed_for_file(entry->size);
        }

        if (new_blocks_needed > actual_blocks_used)
        {
            if (__create_new_blocks(aes_key, new_blocks_needed, actual_blocks_used, entry, entry_id))
                return BLOCK_ERROR;
        }
        else if (new_blocks_needed < actual_blocks_used || new_blocks_needed == 0)
        {
            if (__free_blocks(aes_key, new_blocks_needed, entry))
                return BLOCK_ERROR;
        }
        // If the size changed but new_blocks_needed is the same
        // only change the entry.size

        // Update entry size in the header and write back in directory block
        entry->size = new_size;
        entry->mtime = (uint32_t) time(NULL);
    }
    // if new_size == entry.size, do nothing
    return 0;
}

int entry_truncate(unsigned char* aes_key, struct CryptFS_Entry_ID entry_id, size_t new_size)
{
    if (entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));
        
        // Read the root Entry (corner case)
        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1, root_entry))
            goto err_truncate_entry_root;

         // Truncate treatment of the Entry
        if (__entry_truncate_treatment(aes_key, root_entry, entry_id, new_size))
            goto err_truncate_entry_root;

        // Write Back entry changes in ROO_DIR_BLOCK
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1, root_entry))
            goto err_truncate_entry;

        free(root_entry);
        return 0;

        err_truncate_entry_root:
            free(root_entry);
            return 0;
    }
    else
    {
        if (__search_entry_in_directory(aes_key, &entry_id))
            return BLOCK_ERROR;

        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1, dir))
            goto err_truncate_entry;
        
        // Get the correct Entry
        struct CryptFS_Entry entry = dir->entries[entry_id.directory_index];

        // Truncate treatment of the Entry
        if (__entry_truncate_treatment(aes_key, &entry, entry_id, new_size))
            goto err_truncate_entry;
        
        // Write Back entry changes in BLOCK
        dir->entries[entry_id.directory_index] = entry;
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1, dir))
            goto err_truncate_entry;

        free(dir);
        return 0;
        
        err_truncate_entry:
            free(dir);
            return BLOCK_ERROR;
    }       
    // Do nothing if new_size is equal to entry.size

}

int entry_write_buffer_from(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id,
     size_t start_from, const void* buffer, size_t count)
{
    // Find the real block and index
    if (__search_entry_in_directory(aes_key, &file_entry_id))
        return BLOCK_ERROR;
    
    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    
    if (read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1, dir))
        goto err_write_buffer_entry;
    
    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[file_entry_id.directory_index];

    // Can't write buffer in a directory
    if (entry.type == ENTRY_TYPE_DIRECTORY)
        goto err_write_buffer_entry;

    size_t sum_writing = start_from + count;
    if (sum_writing > entry.size)
    {
        entry_truncate(aes_key, file_entry_id, sum_writing);
        // update entry
        read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1, dir);
        entry = dir->entries[file_entry_id.directory_index];
    }

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
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    
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

    // Update entry timestamp
    entry.mtime = (uint32_t) time(NULL);
    dir->entries[file_entry_id.directory_index] = entry;
    if (write_blocks_with_encryption(aes_key, file_entry_id.directory_block, 1, dir))
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

int entry_write_buffer(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id,
     const void* buffer, size_t count)
{
    return entry_write_buffer_from(aes_key, file_entry_id, 0, buffer, count);
}

ssize_t entry_read_raw_data(unsigned char* aes_key, struct CryptFS_Entry_ID file_entry_id,
     size_t start_from, void* buf, size_t count)
{
    ssize_t result = 0;

    // Find the real block and index
    if (__search_entry_in_directory(aes_key, &file_entry_id))
        return BLOCK_ERROR;

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1, dir))
        goto err_read_entry;
    
    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[file_entry_id.directory_index];

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
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    
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

    // Update entry timestamp
    entry.atime = (uint32_t) time(NULL);
    dir->entries[file_entry_id.directory_index] = entry;
    if (write_blocks_with_encryption(aes_key, file_entry_id.directory_block, 1, dir))
        goto err_read_entry;
    
    free(dir);
    free(block_buffer);
    return result;

    err_read_entry:
        free(dir);
        free(block_buffer);
        return BLOCK_ERROR;
}

/**
 * @brief Entry_delete routine (same for root or other)
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry Pointer to CryptFS_Entry.
 * @param new_size Size to truncate the entry with.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_delete_routine(unsigned char* aes_key, struct CryptFS_Entry* parent_dir_entry,
     uint32_t entry_index)
{
    block_t s_block = parent_dir_entry->start_block;
    struct CryptFS_Entry_ID entry_id = {s_block, entry_index};
    __search_entry_in_directory(aes_key, &entry_id);

    struct CryptFS_Directory *parent_dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
        goto err_entry_delete;
        
    struct CryptFS_Entry entry = parent_dir->entries[entry_index];

    // Check if Directory is empty or if entry exist
    if ((entry.type == ENTRY_TYPE_DIRECTORY && entry.size != 0) || entry.used == 0)
        goto err_entry_delete;
        
    if (entry_truncate(aes_key, entry_id, 0))
        goto err_entry_delete;

    // Update entry;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    entry = parent_dir->entries[entry_index];
    entry.used = 0;
    parent_dir->entries[entry_index] = entry;
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    free(parent_dir);
    return 0;

    err_entry_delete:
            free(parent_dir);
            return BLOCK_ERROR;
}

int entry_delete(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id,
     uint32_t entry_index)
{
    if (parent_dir_entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));

        // Put routine
        if (__entry_delete_routine(aes_key, root_entry, entry_index))
            goto err_entry_delete_root;

        // Update Entry Root entry
        root_entry->size--;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return 0;

        err_entry_delete_root:
            free(root_entry);
            return BLOCK_ERROR;
    }
    else
    {
        // Find the real block and index
        if (__search_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;

        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_entry_delete;
        
        // Get the correct Directory Entry (where is stocked the entry to delete)
        struct CryptFS_Entry parent_dir_entry = dir->entries[parent_dir_entry_id.directory_index];
        if (parent_dir_entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_entry_delete;
        
        // routine start here
        if (__entry_delete_routine(aes_key, &parent_dir_entry, entry_index))
            goto err_entry_delete;
        
        // Update Entry of directory containing the deleted entry       
        dir->entries[parent_dir_entry_id.directory_index].size--;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        return 0;

        err_entry_delete:
            free(dir);
            return BLOCK_ERROR;
        }
    }

/**
 * @brief Routine called by entry_create_empty_file
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify its metadata after adding entry)
 * @param name Name of the empty file.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_create_empty_file_routine(unsigned char* aes_key, struct CryptFS_Entry* entry,
     const char* name, struct CryptFS_Entry_ID parent_dir_entry_id)
{
    uint32_t index = 0;
    
    // Find free index in Directory
    struct CryptFS_Directory *parent_dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    
    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {

            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t) BLOCK_END)
            {
                entry_truncate(aes_key, parent_dir_entry_id, entry->size + 1);
                tmp_block = read_fat_offset(aes_key, s_block);
            }
            s_block = tmp_block;
            if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
                goto err_create_file;
        }
    }
    // Create File
    time_t current_time = time(NULL);
    struct CryptFS_Entry new_file =
    {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = 0,
        .size = 0,
        .uid = getuid(),
        .gid = getgid(),
        .mode = 777,
        .atime = (uint32_t) current_time,
        .mtime = (uint32_t) current_time,
        .ctime = (uint32_t) current_time
    };
    // Name
    strncpy(new_file.name, name, ENTRY_NAME_MAX_LEN - 1);
    new_file.name[ENTRY_NAME_MAX_LEN - 1] = '\0';
    parent_dir->entries[index % NB_ENTRIES_PER_BLOCK] = new_file;

    // Write the block
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    free(parent_dir);
    return index;

    err_create_file:
        free(parent_dir);
        return BLOCK_ERROR;
}

uint32_t entry_create_empty_file(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id,
     const char* name)
{
    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));

        read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry->size--; // update size only at the end if succes of adding file
        }

        int res = __entry_create_empty_file_routine(aes_key, root_entry, name,
             parent_dir_entry_id);

        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file_root;
        }

        index = (uint32_t)res;

        // Update Entry
        root_entry->size++;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

        err_create_file_root:
            free(root_entry);
            return BLOCK_ERROR;
    }
    else
    {
        if (__search_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry = dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);
            entry = dir->entries[parent_dir_entry_id.directory_index];
            entry.size--; // update size only at the end if succes of adding
        }

        // Routine
        int res = __entry_create_empty_file_routine(aes_key, &entry, name,
             parent_dir_entry_id);

        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file;
        }

        index = res;
        // Update Directory size
        entry.size++;
        dir->entries[parent_dir_entry_id.directory_index] = entry;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        return index;

        err_create_file:
            free(dir);
            return BLOCK_ERROR;
    }
}

/**
 * @brief Routine called by entry_create_dir
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify its metadata after adding entry)
 * @param name Name of the future new directory.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_create_dir_routine(unsigned char* aes_key, struct CryptFS_Entry* entry,
     const char* name, struct CryptFS_Entry_ID parent_dir_entry_id)
{
    uint32_t index = 0;
    if (entry->type != ENTRY_TYPE_DIRECTORY)
            return BLOCK_ERROR;
    
    // Find free index in Directory
    struct CryptFS_Directory *parent_dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    
    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {

            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t) BLOCK_END)
            {
                entry_truncate(aes_key, parent_dir_entry_id, entry->size + 1);
                tmp_block = read_fat_offset(aes_key, s_block);
            }
            s_block = tmp_block;
            if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
                goto err_create_file;
        }
    }
    // Create Directory
    time_t current_time = time(NULL);
    struct CryptFS_Entry new_dir =
    {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = 0,
        .size = 0,
        .uid = getuid(),
        .gid = getgid(),
        .mode = 777,
        .atime = (uint32_t) current_time,
        .mtime = (uint32_t) current_time,
        .ctime = (uint32_t) current_time
    };
    // Name
    strncpy(new_dir.name, name, ENTRY_NAME_MAX_LEN - 1);
    new_dir.name[ENTRY_NAME_MAX_LEN - 1] = '\0';
    parent_dir->entries[index % NB_ENTRIES_PER_BLOCK] = new_dir;

    // Write the block
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    free(parent_dir);
    return index;

    err_create_file:
        free(parent_dir);
        return BLOCK_ERROR;
}

uint32_t entry_create_directory(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id,
     const char* name)
{
    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));

        read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry->size--; // update size only at the end if succes of adding
        }
        int res = __entry_create_dir_routine(aes_key, root_entry, name,
             parent_dir_entry_id);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file_root;
        }
        index = (uint32_t)res;

        // Update Entry
        root_entry->size++;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

        err_create_file_root:
            free(root_entry);
            return BLOCK_ERROR;
    }
    else
    {
        if (__search_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry = dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);
            entry = dir->entries[parent_dir_entry_id.directory_index];
            entry.size--; // update size only at the end if succes of adding
        }

        // Routine
        int res = __entry_create_dir_routine(aes_key, &entry, name,
             parent_dir_entry_id);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file;
        }

        index = res;
        // Update Directory size
        entry.size++;
        dir->entries[parent_dir_entry_id.directory_index] = entry;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        return index;

        err_create_file:
            free(dir);
            return BLOCK_ERROR;
    }
}

/**
 * @brief Routine called by entry_create_hardlink
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify its metadata after adding entry)
 * @param name Name of the future hardlink.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param entry_to_link Entry to copy data from.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_create_hardlink_routine(unsigned char* aes_key, struct CryptFS_Entry* entry,
     const char* name, struct CryptFS_Entry_ID parent_dir_entry_id,
         struct CryptFS_Entry entry_to_link)
{
    uint32_t index = 0;
    if (entry->type != ENTRY_TYPE_DIRECTORY)
            return BLOCK_ERROR;
    
    // Find free index in Directory
    struct CryptFS_Directory *parent_dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    
    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {

            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t) BLOCK_END)
            {
                entry_truncate(aes_key, parent_dir_entry_id, entry->size + 1);
                tmp_block = read_fat_offset(aes_key, s_block);
            }
            s_block = tmp_block;
            if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
                goto err_create_file;
        }
    }
    // Create Hardlink
    time_t current_time = time(NULL);
    struct CryptFS_Entry new_hard =
    {
        .used = 1,
        .type = ENTRY_TYPE_HARDLINK,
        .start_block = entry_to_link.start_block,
        .size = entry_to_link.size,
        .uid = getuid(),
        .gid = getgid(),
        .mode = 777,
        .atime = (uint32_t) current_time,
        .mtime = (uint32_t) current_time,
        .ctime = (uint32_t) current_time
    };
    // Name
    strncpy(new_hard.name, name, ENTRY_NAME_MAX_LEN - 1);
    new_hard.name[ENTRY_NAME_MAX_LEN - 1] = '\0';
    parent_dir->entries[index % NB_ENTRIES_PER_BLOCK] = new_hard;

    // Write the block
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    free(parent_dir);
    return index;

    err_create_file:
        free(parent_dir);
        return BLOCK_ERROR;
}


uint32_t entry_create_hardlink(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id,
     const char* name, struct CryptFS_Entry_ID target_entry_id)
{
    uint32_t index;
    // Exctract entry to Link
    if (__search_entry_in_directory(aes_key, &target_entry_id))
            return BLOCK_ERROR;
    
    // allocate struct for reading target_link_block
        struct CryptFS_Directory *target_link_dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, target_entry_id.directory_block, 1, target_link_dir))
        goto err_create_file_init;

    struct CryptFS_Entry entry_to_link = target_link_dir->entries[target_entry_id.directory_index];

    // Test if the entry_to_link is a file
    if (entry_to_link.type != ENTRY_TYPE_FILE)
        goto err_create_file_init;

    if (parent_dir_entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));

        read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry->size--; // update size only at the end if succes of adding
        }
        int res = __entry_create_hardlink_routine(aes_key, root_entry, name,
             parent_dir_entry_id, entry_to_link);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file_root;
        }
        index = (uint32_t)res;

        // Update Entry
        root_entry->size++;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        free(target_link_dir);
        return index;

        err_create_file_root:
            free(root_entry);
            free(target_link_dir);
            return BLOCK_ERROR;
    }
    else
    {
        if (__search_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;

        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        // Reading block
        if (read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Extract Entry
        struct CryptFS_Entry entry = dir->entries[parent_dir_entry_id.directory_index];

        // Check if it is effectively an Directory
        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        
        int initiated = 0; // if initiated still 0 =, directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);
            entry = dir->entries[parent_dir_entry_id.directory_index];
            entry.size--; // update size only at the end if succes of adding
            initiated = 1;
        }

        // Routine
        int res = __entry_create_hardlink_routine(aes_key, &entry, name,
             parent_dir_entry_id, entry_to_link);

        // Check success
        if (res == BLOCK_ERROR)
        {
            // if initiated != 0, restore the block allowed
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file;
        }

        index = res;
        // Update Directory size
        entry.size++;
        dir->entries[parent_dir_entry_id.directory_index] = entry;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        free(target_link_dir);
        return index;

        err_create_file:
            free(dir);
            free(target_link_dir);
            return BLOCK_ERROR;
    }

    err_create_file_init:
        free(target_link_dir);
        return BLOCK_ERROR;
}


/**
 * @brief Routine called by entry_create_symlink
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify its metadata after adding entry)
 * @param name Name of the future hardlink.
 * @param parent_dir_entry_id structure composed of the block number where starts a struct CryptFS_Directory and the index of the entry in this current CryptFS_Directory.
 * @param symlink Path to the linked entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_create_symlink_routine(unsigned char* aes_key, struct CryptFS_Entry* entry,
     const char* name, struct CryptFS_Entry_ID parent_dir_entry_id, const char *symlink)
{
    uint32_t index = 0;
    
    // Find free index in Directory
    struct CryptFS_Directory *parent_dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));
    
    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {

            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t) BLOCK_END)
            {
                entry_truncate(aes_key, parent_dir_entry_id, entry->size + 1);
                tmp_block = read_fat_offset(aes_key, s_block);
            }
            s_block = tmp_block;
            if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
                goto err_create_file;
        }
    }
    // Create File
    time_t current_time = time(NULL);
    struct CryptFS_Entry new_sym =
    {
        .used = 1,
        .type = ENTRY_TYPE_SYMLINK,
        .start_block = 0,
        .size = 0,
        .uid = getuid(),
        .gid = getgid(),
        .mode = 777,
        .atime = (uint32_t) current_time,
        .mtime = (uint32_t) current_time,
        .ctime = (uint32_t) current_time
    };
    // Name
    strncpy(new_sym.name, name, ENTRY_NAME_MAX_LEN - 1);
    new_sym.name[ENTRY_NAME_MAX_LEN - 1] = '\0';
    parent_dir->entries[index % NB_ENTRIES_PER_BLOCK] = new_sym;

    // Write the block
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    // Write symblink in file
    struct CryptFS_Entry_ID entry_id = {s_block, index % NB_ENTRIES_PER_BLOCK};
    size_t sym_size = strlen(symlink);
    if (symlink[sym_size - 1] == '\0')
        sym_size--;
    entry_write_buffer(aes_key, entry_id, symlink, sym_size);

    free(parent_dir);
    return index;

    err_create_file:
        free(parent_dir);
        return BLOCK_ERROR;
}

uint32_t entry_create_symlink(unsigned char* aes_key, struct CryptFS_Entry_ID parent_dir_entry_id,
     const char* name, const char *symlink)
{
    if (!is_readable_ascii(symlink) || strlen(symlink) == 0)
        return BLOCK_ERROR;
    
    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_DIR_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Entry));

        read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry->size--; // update size only at the end if succes of adding
        }
        int res = __entry_create_symlink_routine(aes_key, root_entry, name,
             parent_dir_entry_id, symlink);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file_root;
        }
        index = (uint32_t)res;

        // Update Entry
        root_entry->size++;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

        err_create_file_root:
            free(root_entry);
            return BLOCK_ERROR;
    }
    else
    {
        if (__search_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir =
            xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                            sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry = dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated = 0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);
            entry = dir->entries[parent_dir_entry_id.directory_index];
            entry.size--; // update size only at the end if succes of adding
        }

        // Routine
        int res = __entry_create_symlink_routine(aes_key, &entry, name,
             parent_dir_entry_id, symlink);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file;
        }

        index = res;
        // Update Directory size
        entry.size++;
        dir->entries[parent_dir_entry_id.directory_index] = entry;
        write_blocks_with_encryption(aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        return index;

        err_create_file:
            free(dir);
            return BLOCK_ERROR;
    }
}