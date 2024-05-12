#include "entries.h"

#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ascii.h"
#include "block.h"
#include "cryptfs.h"
#include "fat.h"
#include "print.h"
#include "xalloc.h"

int __blocks_needed_for_file(size_t size)
{
    int result = size / CRYPTFS_BLOCK_SIZE_BYTES;
    if (size % CRYPTFS_BLOCK_SIZE_BYTES != (float)0)
    {
        return result + 1;
    }
    else
    {
        return result;
    }
}

int __blocks_needed_for_dir(size_t size)
{
    int result = size / NB_ENTRIES_PER_BLOCK;
    if (size % NB_ENTRIES_PER_BLOCK != (float)0)
    {
        return result + 1;
    }
    else
    {
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
 * @param entry_id structure composed of the block number where starts a struct
 * CryptFS_Directory and the index of the entry in this current
 * CryptFS_Directory.
 * @return 0 when success, -1 otherwise.
 */
static int __create_new_blocks(const unsigned char *aes_key,
                               size_t new_blocks_needed,
                               size_t actual_blocks_used,
                               struct CryptFS_Entry *entry,
                               struct CryptFS_Entry_ID entry_id)
{
    struct CryptFS_Directory *init_dir = xaligned_calloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));
    init_dir->current_directory_entry = entry_id;
    // If entry is empty, initialize start_block
    if (entry->start_block == 0)
    {
        block_t start = find_first_free_block_safe(aes_key);
        if (start == (size_t)BLOCK_ERROR)
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
    while ((int)read_fat_offset(aes_key, end_block) != BLOCK_END)
    {
        end_block = (uint64_t)read_fat_offset(aes_key, end_block);
    }
    while (actual_blocks_used < new_blocks_needed)
    {
        block_t new_end = find_first_free_block_safe(aes_key);
        if (new_end == (size_t)BLOCK_ERROR)
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
static int __free_blocks(const unsigned char *aes_key, size_t new_blocks_needed,
                         struct CryptFS_Entry *entry)
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
            if (end_block == (size_t)BLOCK_ERROR)
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
            end_block = (uint64_t)read_fat_offset(aes_key, end_block);
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
 * @brief Loop to truncate entry.
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer to CryptFS_Entry.
 * @param entry_id Structure, composed of the block number where a struct
 * CryptFS_Directory starts and the index of the entry within this current
 * CryptFS_Directory, serves to uniquely identify an entry on the file system.
 * @param new_size Size to truncate the entry with.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_truncate_treatment(const unsigned char *aes_key,
                                      struct CryptFS_Entry *entry,
                                      struct CryptFS_Entry_ID entry_id,
                                      size_t new_size)
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
            if (__create_new_blocks(aes_key, new_blocks_needed,
                                    actual_blocks_used, entry, entry_id))
                return BLOCK_ERROR;
        }
        else if (new_blocks_needed < actual_blocks_used
                 || new_blocks_needed == 0)
        {
            if (__free_blocks(aes_key, new_blocks_needed, entry))
                return BLOCK_ERROR;
        }
        // If the size changed but new_blocks_needed is the same
        // only change the entry.size

        // Update entry size in the header and write back in directory block
        entry->size = new_size;
        entry->mtime = (uint32_t)time(NULL);
    }
    if (new_size == 0)
        entry->used = 0;
    // if new_size == entry.size, do nothing
    return 0;
}

struct CryptFS_Entry *get_entry_from_id(const unsigned char *aes_key,
                                        struct CryptFS_Entry_ID entry_id)
{
    // Correct Entry ID if needed
    if (goto_entry_in_directory(aes_key, &entry_id))
        return NULL;

    struct CryptFS_Entry *entry =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    if (entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                        entry))
            return NULL;
    }
    else
    {
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                        dir))
            return NULL;
        *entry = dir->entries[entry_id.directory_index];
        free(dir);
    }
    return entry;
}

// TODO: Tests
int write_entry_from_id(const unsigned char *aes_key,
                        struct CryptFS_Entry_ID entry_id,
                        struct CryptFS_Entry *entry)
{
    // Sanitize entry_id
    if (goto_entry_in_directory(aes_key, &entry_id))
        return BLOCK_ERROR;

    if (entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        char *entry_block = xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                                           CRYPTFS_BLOCK_SIZE_BYTES);
        memcpy(entry_block, entry, sizeof(struct CryptFS_Entry));
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1,
                                         entry_block))
            return BLOCK_ERROR;
        free(entry_block);
    }
    else
    {
        // Read the directory block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                        dir))
        {
            free(dir);
            return BLOCK_ERROR;
        }

        // Write the entry in the directory block
        dir->entries[entry_id.directory_index] = *entry;

        // Write back the directory block
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1,
                                         dir))
        {
            free(dir);
            return BLOCK_ERROR;
        }

        free(dir);
    }

    return 0;
}

struct CryptFS_Entry_ID *get_entry_by_path(const unsigned char *aes_key,
                                           const char *path)
{
    if (path == NULL || strlen(path) == 0 || aes_key == NULL)
        return (void *)BLOCK_ERROR;

    // Copie du chemin pour éviter de modifier l'original
    char path_copy[PATH_MAX] = { 0 };
    strncpy(path_copy, path, strlen(path));

    // Initialisation de l'ID de l'entrée à la racine
    struct CryptFS_Entry_ID *entry_id =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    entry_id->directory_block = ROOT_ENTRY_BLOCK;
    entry_id->directory_index = 0;

    // Parcours du chemin, répertoire par répertoire
    char *dir_name = strtok(path_copy, "/");
    while (dir_name != NULL)
    {
        // Récupération de l'entrée actuelle
        struct CryptFS_Entry *entry = get_entry_from_id(aes_key, *entry_id);

        // Si l'entrée n'existe pas, renvoie une erreur
        if (!entry)
        {
            free(entry_id);
            return (void *)ENTRY_NO_SUCH;
        }

        // Si l'entrée n'est pas un répertoire et qu'il reste des éléments dans
        // le chemin, renvoie une erreur
        if (entry->type != ENTRY_TYPE_DIRECTORY && strtok(NULL, "/") != NULL)
        {
            free(entry);
            free(entry_id);
            return (void *)ENTRY_NO_SUCH;
        }

        // Goto struct CryptFS_Directory
        // entry_id->directory_block = entry->start_block;
        // entry_id->directory_index = 0;

        // Recherche de l'entrée correspondant au nom du répertoire dans le
        // répertoire actuel
        bool found_entry = false;
        struct CryptFS_Entry_ID *test_entry_id = NULL;
        for (uint64_t i = 0; i < entry->size; i++)
        {
            test_entry_id = goto_used_entry_in_directory(aes_key, *entry_id, i);

            struct CryptFS_Entry *test_entry =
                get_entry_from_id(aes_key, *test_entry_id);

            if (test_entry && strcmp(test_entry->name, dir_name) == 0)
            {
                found_entry = true;
                free(test_entry);
                break;
            }

            free(test_entry);
            free(test_entry_id);
        }

        // Si l'entrée n'a pas été trouvée, renvoie une erreur
        if (!found_entry)
        {
            free(entry);
            free(entry_id);
            return (void *)ENTRY_NO_SUCH;
        }

        dir_name = strtok(NULL, "/");

        // Copy test_entry_id to entry_id
        memcpy(entry_id, test_entry_id, sizeof(struct CryptFS_Entry_ID));
        free(test_entry_id);
        free(entry);
    }

    return entry_id;
}

/**
 * @brief Helper function for all create_*_by_path functions.
 * The main purpose of this function is :
 * - Check if the entry already exists.
 * - Get the parent directory entry ID. (where the new entry will be created)
 * - Get the parent directory CryptFS_Directory block.
 * (parent directory entry -> start_block)
 * - Get the base name of the entry to create. (the name of the file or
 * whatever)
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param path The path of the entry to create.
 * @param parent_dir_entry_id Parent directory of the future entry entry ID.
 * (returned)
 * @param parent_dir_entry_dir Already calculated block of the parent directory
 * struct CryptFS_Directory.
 * (returned)
 * @param base_name Name of the entry to create.
 * (returned)
 */
static int __create_entry_by_path(const unsigned char *aes_key,
                                  const char *path,
                                  struct CryptFS_Entry_ID **parent_dir_entry_id,
                                  char **base_name)
{
    // Check if file already exists
    struct CryptFS_Entry_ID *entry_id = get_entry_by_path(aes_key, path);
    switch ((uint64_t)entry_id)
    {
    case BLOCK_ERROR:
        return BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        break;
    default:
        free(entry_id);
        return ENTRY_EXISTS;
    }
    // Get the parent directory path using dirname()
    char path_copy[PATH_MAX] = { 0 };
    strncpy(path_copy, path, strlen(path));
    char *dir_name = dirname(path_copy);

    // Get the parent directory entry ID
    *parent_dir_entry_id = get_entry_by_path(aes_key, dir_name);

    switch ((uint64_t)parent_dir_entry_id)
    {
    case BLOCK_ERROR:
        free(*parent_dir_entry_id);
        free(entry_id);
        return BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        free(*parent_dir_entry_id);
        free(entry_id);
        return ENTRY_NO_SUCH;
    default:
        // Get the basename of the path
        strncpy(path_copy, path, strlen(path));
        *base_name = xcalloc(NAME_MAX + 1, 1);
        char *base_name_tmp = basename(path_copy);
        strncpy(*base_name, base_name_tmp, strlen(base_name_tmp));
    }

    return 0;
}

struct CryptFS_Entry_ID *create_file_by_path(const unsigned char *aes_key,
                                             const char *path)
{
    // Create the empty file at the parent directory level
    struct CryptFS_Entry_ID *parent_dir_entry_id = NULL;
    char *base_name = NULL;

    switch (
        __create_entry_by_path(aes_key, path, &parent_dir_entry_id, &base_name))
    {
    case BLOCK_ERROR:
        return (void *)BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        return (void *)ENTRY_NO_SUCH;
    case ENTRY_EXISTS:
        return (void *)ENTRY_EXISTS;
    default:
        // Create the empty file (and remember its index in the parent
        // directory)
        uint32_t entry_index_in_dir =
            entry_create_empty_file(aes_key, *parent_dir_entry_id, base_name);

        if (entry_index_in_dir == (uint32_t)BLOCK_ERROR)
            return (void *)BLOCK_ERROR;

        // Get the parent directory entry.start_block (struct CryptFS_Directory)
        struct CryptFS_Entry *parent_dir_entry =
            get_entry_from_id(aes_key, *parent_dir_entry_id);
        block_t parent_dir_entry_dir = parent_dir_entry->start_block;
        free(parent_dir_entry);

        // Fill the returned structure
        // (parent_dir_entry_dir, entry_index_in_dir)
        struct CryptFS_Entry_ID *new_file_entry_id = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
        new_file_entry_id->directory_block = parent_dir_entry_dir;
        new_file_entry_id->directory_index = entry_index_in_dir;

        free(base_name);
        free(parent_dir_entry_id);

        return new_file_entry_id;
    }

    // Never reached, but el compilator is happy
    return NULL;
}

struct CryptFS_Entry_ID *create_directory_by_path(const unsigned char *aes_key,
                                                  const char *path)
{
    // Create the empty directory at the parent directory level
    struct CryptFS_Entry_ID *parent_dir_entry_id = NULL;
    char *base_name = NULL;

    switch (
        __create_entry_by_path(aes_key, path, &parent_dir_entry_id, &base_name))
    {
    case BLOCK_ERROR:
        return (void *)BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        return (void *)ENTRY_NO_SUCH;
    case ENTRY_EXISTS:
        return (void *)ENTRY_EXISTS;
    default:
        // Create the empty directory (and remember its index in the parent
        // directory)
        uint32_t entry_index_in_dir =
            entry_create_directory(aes_key, *parent_dir_entry_id, base_name);

        if (entry_index_in_dir == (uint32_t)BLOCK_ERROR)
            return (void *)BLOCK_ERROR;

        // Get the parent directory entry.start_block (struct CryptFS_Directory)
        struct CryptFS_Entry *parent_dir_entry =
            get_entry_from_id(aes_key, *parent_dir_entry_id);
        block_t parent_dir_entry_dir = parent_dir_entry->start_block;
        free(parent_dir_entry);

        // Fill the returned structure
        // (parent_dir_entry_dir, entry_index_in_dir)
        struct CryptFS_Entry_ID *new_dir_entry_id = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
        new_dir_entry_id->directory_block = parent_dir_entry_dir;
        new_dir_entry_id->directory_index = entry_index_in_dir;

        free(base_name);
        free(parent_dir_entry_id);

        return new_dir_entry_id;
    }
    // Never reached, but el compilator is happy
    return NULL;
}

struct CryptFS_Entry_ID *create_symlink_by_path(const unsigned char *aes_key,
                                                const char *path,
                                                const char *symlink)
{
    // Create the empty symlink at the parent directory level
    struct CryptFS_Entry_ID *parent_dir_entry_id = NULL;
    char *base_name = NULL;

    switch (
        __create_entry_by_path(aes_key, path, &parent_dir_entry_id, &base_name))
    {
    case BLOCK_ERROR:
        return (void *)BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        return (void *)ENTRY_NO_SUCH;
    case ENTRY_EXISTS:
        return (void *)ENTRY_EXISTS;
    default:
        // Create the empty symlink (and remember its index in the parent
        // directory)
        uint32_t entry_index_in_dir = entry_create_symlink(
            aes_key, *parent_dir_entry_id, base_name, symlink);

        if (entry_index_in_dir == (uint32_t)BLOCK_ERROR)
            return (void *)BLOCK_ERROR;

        // Get the parent directory entry.start_block (struct CryptFS_Directory)
        struct CryptFS_Entry *parent_dir_entry =
            get_entry_from_id(aes_key, *parent_dir_entry_id);
        block_t parent_dir_entry_dir = parent_dir_entry->start_block;
        free(parent_dir_entry);

        // Fill the returned structure
        // (parent_dir_entry_dir, entry_index_in_dir)
        struct CryptFS_Entry_ID *new_symlink_entry_id = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
        new_symlink_entry_id->directory_block = parent_dir_entry_dir;
        new_symlink_entry_id->directory_index = entry_index_in_dir;

        free(base_name);
        free(parent_dir_entry_id);

        return new_symlink_entry_id;
    }
    // Never reached, but el compilator is happy
    return NULL;
}

struct CryptFS_Entry_ID *create_hardlink_by_path(const unsigned char *aes_key,
                                                 const char *path,
                                                 const char *target_path)
{
    // Create the empty hardlink at the parent directory level
    struct CryptFS_Entry_ID *parent_dir_entry_id = NULL;
    char *base_name = NULL;

    switch (
        __create_entry_by_path(aes_key, path, &parent_dir_entry_id, &base_name))
    {
    case BLOCK_ERROR:
        return (void *)BLOCK_ERROR;
    case ENTRY_NO_SUCH:
        return (void *)ENTRY_NO_SUCH;
    case ENTRY_EXISTS:
        return (void *)ENTRY_EXISTS;
    default:
        // Get hardlink entry ID by path
        struct CryptFS_Entry_ID *hardlink_entry_id =
            get_entry_by_path(aes_key, target_path);

        // If the target entry does not exist, return an error
        if (hardlink_entry_id == (void *)ENTRY_NO_SUCH)
        {
            free(base_name);
            free(parent_dir_entry_id);
            return (void *)ENTRY_NO_SUCH;
        }

        // Create the hardlink (and remember its index in the parent directory)
        uint32_t entry_index_in_dir = entry_create_hardlink(
            aes_key, *parent_dir_entry_id, base_name, *hardlink_entry_id);

        if (entry_index_in_dir == (uint32_t)BLOCK_ERROR)
            return (void *)BLOCK_ERROR;

        // Get the parent directory entry.start_block (struct CryptFS_Directory)
        struct CryptFS_Entry *parent_dir_entry =
            get_entry_from_id(aes_key, *parent_dir_entry_id);
        block_t parent_dir_entry_dir = parent_dir_entry->start_block;
        free(parent_dir_entry);

        // Fill the returned structure
        // (parent_dir_entry_dir, entry_index_in_dir)
        struct CryptFS_Entry_ID *new_hardlink_entry_id = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
        new_hardlink_entry_id->directory_block = parent_dir_entry_dir;
        new_hardlink_entry_id->directory_index = entry_index_in_dir;

        free(base_name);
        free(parent_dir_entry_id);

        return new_hardlink_entry_id;
    }

    // Never reached, but el compilator is happy
    return NULL;
}

int delete_entry_by_path(const unsigned char *aes_key, const char *path)
{
    // Get the entry ID of the entry to delete
    struct CryptFS_Entry_ID *entry_id = get_entry_by_path(aes_key, path);

    // If the entry does not exist, return an error
    if (entry_id == (void *)ENTRY_NO_SUCH)
        return ENTRY_NO_SUCH;

    // FIXME: Not optimal, but it works
    char parent_path[PATH_MAX] = { 0 };
    strncpy(parent_path, path, strlen(path));
    char *parent_dir = dirname(parent_path);

    // Get the parent directory entry ID
    struct CryptFS_Entry_ID *parent_dir_entry_id =
        get_entry_by_path(aes_key, parent_dir);

    // If there is an error here, this is fatal!
    if ((int64_t)parent_dir_entry_id < 0)
    {
        free(entry_id);
        return BLOCK_ERROR;
    }

    if (entry_delete(aes_key, *entry_id) != 0)
    {
        free(entry_id);
        free(parent_dir_entry_id);
        return BLOCK_ERROR;
    }

    free(entry_id);
    free(parent_dir_entry_id);
    return 0;
}

int goto_entry_in_directory(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID *entry_id)
{
    if (entry_id->directory_index > NB_ENTRIES_PER_BLOCK - 1)
    {
        int count = __blocks_needed_for_dir(entry_id->directory_index + 1);
        entry_id->directory_index =
            entry_id->directory_index % NB_ENTRIES_PER_BLOCK;
        while (count > 1 && read_fat_offset(aes_key, entry_id->directory_block))
        {
            entry_id->directory_block =
                read_fat_offset(aes_key, entry_id->directory_block);
            count--;
        }
        if (count > 1)
            return -1;
    }
    return 0;
}

struct CryptFS_Entry_ID *
goto_used_entry_in_directory(const unsigned char *aes_key,
                             struct CryptFS_Entry_ID directory_entry_id,
                             size_t index)
{
    // Get entry by id
    struct CryptFS_Entry *entry =
        get_entry_from_id(aes_key, directory_entry_id);

    if (index + 1 > entry->size)
    {
        free(entry);
        return (void *)ENTRY_NO_SUCH;
    }

    // Using directory_entry_id for iterating over the directory
    directory_entry_id.directory_block = entry->start_block;
    directory_entry_id.directory_index = 0;
    free(entry);

    while (true)
    {
        if (directory_entry_id.directory_index > NB_ENTRIES_PER_BLOCK - 1)
        {
            directory_entry_id.directory_block =
                read_fat_offset(aes_key, directory_entry_id.directory_block);
            directory_entry_id.directory_index = 0;
        }
        else
        {
            // Get entry by id
            entry = get_entry_from_id(aes_key, directory_entry_id);
            bool is_used = entry->used == 1;
            free(entry);
            if (is_used)
            {
                if (index == 0)
                    break;
                index--;
            }
            directory_entry_id.directory_index++;
        }
    }

    struct CryptFS_Entry_ID *entry_id =
        xmalloc(1, sizeof(struct CryptFS_Entry_ID));
    entry_id->directory_block = directory_entry_id.directory_block;
    entry_id->directory_index = directory_entry_id.directory_index;

    return entry_id;
}

int entry_truncate(const unsigned char *aes_key,
                   struct CryptFS_Entry_ID entry_id, size_t new_size)
{
    if (entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

        // Read the root Entry (corner case)
        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                        root_entry))
            goto err_truncate_entry_root;

        // Truncate treatment of the Entry
        if (__entry_truncate_treatment(aes_key, root_entry, entry_id, new_size))
            goto err_truncate_entry_root;

        // Write Back entry changes in ROO_DIR_BLOCK
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1,
                                         root_entry))
            goto err_truncate_entry;

        free(root_entry);
        return 0;

    err_truncate_entry_root:
        free(root_entry);
        return 0;
    }
    else
    {
        if (goto_entry_in_directory(aes_key, &entry_id))
            return BLOCK_ERROR;

        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                        dir))
            goto err_truncate_entry;

        // Get the correct Entry
        struct CryptFS_Entry entry = dir->entries[entry_id.directory_index];

        // Truncate treatment of the Entry
        if (__entry_truncate_treatment(aes_key, &entry, entry_id, new_size))
            goto err_truncate_entry;

        // Write Back entry changes in BLOCK
        dir->entries[entry_id.directory_index] = entry;
        if (write_blocks_with_encryption(aes_key, entry_id.directory_block, 1,
                                         dir))
            goto err_truncate_entry;

        free(dir);
        return 0;

    err_truncate_entry:
        free(dir);
        return BLOCK_ERROR;
    }
    // Do nothing if new_size is equal to entry.size
}

int entry_write_buffer_from(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID file_entry_id,
                            size_t start_from, const void *buffer, size_t count)
{
    // Find the real block and index
    if (goto_entry_in_directory(aes_key, &file_entry_id))
        return BLOCK_ERROR;

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1,
                                    dir))
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
        read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1,
                                    dir);
        entry = dir->entries[file_entry_id.directory_index];
    }

    block_t s_block = entry.start_block;
    int count_blocks = start_from
        / CRYPTFS_BLOCK_SIZE_BYTES; // Number of the block to start writing
    // int r_start = start_from % CRYPTFS_BLOCK_SIZE_BYTES; // Relative starting
    // index to the start writing block
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
            if (s_block == (block_t)BLOCK_ERROR)
                goto err_write_buffer_entry_2;
            start_from = 0;
            modulo_index = 0;
            if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
                memset(block_buffer, '\0', CRYPTFS_BLOCK_SIZE_BYTES);
        }

        block_buffer[start_from + modulo_index] = ((char *)buffer)[i];
        modulo_index++;
    }

    // Write back the last block_buffer
    if (write_blocks_with_encryption(aes_key, s_block, 1, block_buffer))
        goto err_write_buffer_entry_2;

    // Update entry timestamp
    entry.mtime = (uint32_t)time(NULL);
    dir->entries[file_entry_id.directory_index] = entry;
    if (write_blocks_with_encryption(aes_key, file_entry_id.directory_block, 1,
                                     dir))
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

int entry_write_buffer(const unsigned char *aes_key,
                       struct CryptFS_Entry_ID file_entry_id,
                       const void *buffer, size_t count)
{
    return entry_write_buffer_from(aes_key, file_entry_id, 0, buffer, count);
}

ssize_t entry_read_raw_data(const unsigned char *aes_key,
                            struct CryptFS_Entry_ID file_entry_id,
                            size_t start_from, void *buf, size_t count)
{
    ssize_t result = 0;

    // Find the real block and index
    if (goto_entry_in_directory(aes_key, &file_entry_id))
    {
        print_error("entry_read_raw_data: goto_entry_in_directory(%p,%p)\n",
                    aes_key, &file_entry_id);
        return BLOCK_ERROR;
    }

    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, file_entry_id.directory_block, 1,
                                    dir))
    {
        print_error(
            "entry_read_raw_data: read_blocks_with_decryption(%p,%lu,%p,%p)\n",
            aes_key, file_entry_id.directory_block, 1, dir);
        goto err_read_entry;
    }

    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[file_entry_id.directory_index];

    // Check if the offset to read is correct
    // If the offset is greater than the size of the entry, return 0
    if (start_from >= entry.size)
    {
        free(dir);
        return 0;
    }

    if (entry.size < start_from + count)
    {
        free(dir);
        return entry_read_raw_data(aes_key, file_entry_id, start_from, buf,
                                   entry.size - start_from);
    }

    sblock_t s_block = entry.start_block;
    while (start_from >= CRYPTFS_BLOCK_SIZE_BYTES)
    {
        s_block = read_fat_offset(aes_key, s_block);
        if (s_block < 0)
        {
            print_error("entry_read_raw_data: read_fat_offset(%p,%lu)\n",
                        aes_key, s_block);
            goto err_read_entry;
        }
        start_from -= CRYPTFS_BLOCK_SIZE_BYTES;
    }

    // allocate block_buffer to read block
    char *block_buffer =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // If block is empty, return BLOCK_ERROR
    if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
    {
        print_error(
            "entry_read_raw_data: read_blocks_with_decryption(%p,%lu,%p,%p)\n",
            aes_key, s_block, 1, block_buffer);
        goto err_read_entry2;
    }

    size_t modulo_index = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (start_from + modulo_index >= CRYPTFS_BLOCK_SIZE_BYTES)
        {
            s_block = read_fat_offset(aes_key, s_block);
            if (s_block == (sblock_t)BLOCK_ERROR)
            {
                print_error("entry_read_raw_data: read_fat_offset(%p,%lu)\n",
                            aes_key, s_block);
                goto err_read_entry2;
            }
            start_from = 0;
            modulo_index = 0;
            if (read_blocks_with_decryption(aes_key, s_block, 1, block_buffer))
            {
                print_error("entry_read_raw_data: "
                            "read_blocks_with_decryption(%p,%lu,%p,%p)\n",
                            aes_key, s_block, 1, block_buffer);
                goto err_read_entry2;
            }
        }
        ((char *)buf)[i] = block_buffer[start_from + modulo_index];
        modulo_index++;
        result++;
    }

    // Update entry timestamp
    entry.atime = (uint32_t)time(NULL);
    dir->entries[file_entry_id.directory_index] = entry;
    if (write_blocks_with_encryption(aes_key, file_entry_id.directory_block, 1,
                                     dir))
    {
        print_error(
            "entry_read_raw_data: write_blocks_with_encryption(%p,%lu,%p,%p)\n",
            aes_key, file_entry_id.directory_block, 1, dir);
        goto err_read_entry2;
    }

    free(dir);
    free(block_buffer);
    return result;

err_read_entry2:
    free(block_buffer);
err_read_entry:
    free(dir);
    return BLOCK_ERROR;
}

/**
 * @brief Entry_delete routine (same for root or other)
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param parent_dir_entry Pointer to the CryptFS_Entry of the parent directory.
 * @param new_size Size to truncate the entry with.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
// static int __entry_delete_routine(const unsigned char *aes_key,
//                                   struct CryptFS_Entry *parent_dir_entry,
//                                   uint32_t entry_index)
// {
//     block_t s_block = parent_dir_entry->start_block;
//     struct CryptFS_Entry_ID entry_id = { s_block, entry_index };
//     goto_entry_in_directory(aes_key, &entry_id);

//     struct CryptFS_Directory *parent_dir = xaligned_alloc(
//         CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));
//     if (read_blocks_with_decryption(aes_key, s_block, 1, parent_dir))
//         goto err_entry_delete;

//     // FIXME: Overflow in case of entry_index > NB_ENTRIES_PER_BLOCK?
//     // @clarelsalassa
//     struct CryptFS_Entry entry = parent_dir->entries[entry_index];

//     // Check if Directory is empty or if entry exist
//     if ((entry.type == ENTRY_TYPE_DIRECTORY && entry.size != 0)
//         || entry.used == 0)
//         goto err_entry_delete;

//     if (entry_truncate(aes_key, entry_id, 0))
//         goto err_entry_delete;

//     // Update entry;
//     read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
//     entry = parent_dir->entries[entry_index];
//     entry.used = 0;
//     parent_dir->entries[entry_index] = entry;
//     write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

//     free(parent_dir);
//     return 0;

// err_entry_delete:
//     free(parent_dir);
//     return BLOCK_ERROR;
// }

int entry_delete(const unsigned char *aes_key, struct CryptFS_Entry_ID entry_id)
{
    if (entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Can't delete root directory
        return BLOCK_ERROR;
    }

    // Allocate struct for reading the directory_block where is the entry_id
    struct CryptFS_Directory *dir_block_buff = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));
    read_blocks_with_decryption(aes_key, entry_id.directory_block, 1,
                                dir_block_buff);

    // Check the entry_id type
    if (dir_block_buff->entries[entry_id.directory_index].type
            == ENTRY_TYPE_DIRECTORY
        && dir_block_buff->entries[entry_id.directory_index].size != 0)
    {
        free(dir_block_buff);
        return BLOCK_ERROR;
    }

    // Get the directory_entry_id of the actual directory
    struct CryptFS_Entry_ID dir_entry_id =
        dir_block_buff->current_directory_entry;

    struct CryptFS_Entry *dir_entry =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // Update Directory Entry
    if (dir_entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // If the actual directory is the Root, then the entry is tacking the
        // entire block
        read_blocks_with_decryption(aes_key, dir_entry_id.directory_block, 1,
                                    dir_entry);
        dir_entry->size--;
        write_blocks_with_encryption(aes_key, dir_entry_id.directory_block, 1,
                                     dir_entry);
    }
    else
    {
        // Read block where the directory Entry is stocked
        read_blocks_with_decryption(aes_key, dir_entry_id.directory_block, 1,
                                    dir_block_buff);
        *dir_entry = dir_block_buff->entries[dir_entry_id.directory_index];
        dir_entry->size--;
        dir_block_buff->entries[dir_entry_id.directory_index] = *dir_entry;
        write_blocks_with_encryption(aes_key, dir_entry_id.directory_block, 1,
                                     dir_block_buff);
    }

    entry_truncate(aes_key, entry_id, 0);

    free(dir_block_buff);
    free(dir_entry);
    return 0;
}

/**
 * @brief Routine called by entry_create_empty_file
 *
 * @param aes_key The AES key used for encryption/decryption.
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify
 * its metadata after adding entry)
 * @param name Name of the empty file.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int
__entry_create_empty_file_routine(const unsigned char *aes_key,
                                  struct CryptFS_Entry *entry, const char *name,
                                  struct CryptFS_Entry_ID parent_dir_entry_id)
{
    uint32_t index = 0;

    // Find free index in Directory
    struct CryptFS_Directory *parent_dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {
            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t)BLOCK_END)
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
    struct CryptFS_Entry new_file = { .used = 1,
                                      .type = ENTRY_TYPE_FILE,
                                      .start_block = 0,
                                      .size = 0,
                                      .uid = getuid(),
                                      .gid = getgid(),
                                      .mode = 0777,
                                      .atime = (uint32_t)current_time,
                                      .mtime = (uint32_t)current_time,
                                      .ctime = (uint32_t)current_time };
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

uint32_t entry_create_empty_file(const unsigned char *aes_key,
                                 struct CryptFS_Entry_ID parent_dir_entry_id,
                                 const char *name)
{
    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

        read_blocks_with_decryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry->size--; // update size only at the end if succes of
                                // adding file
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

    err_create_file_root:
        free(root_entry);
        return BLOCK_ERROR;
    }
    else
    {
        if (goto_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry =
            dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir);
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, dir);

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
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify
 * its metadata after adding entry)
 * @param name Name of the future new directory.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int
__entry_create_dir_routine(const unsigned char *aes_key,
                           struct CryptFS_Entry *entry, const char *name,
                           struct CryptFS_Entry_ID parent_dir_entry_id)
{
    uint32_t index = 0;
    if (entry->type != ENTRY_TYPE_DIRECTORY)
        return BLOCK_ERROR;

    // Find free index in Directory
    struct CryptFS_Directory *parent_dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {
            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t)BLOCK_END)
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
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .size = 0,
                                     .uid = getuid(),
                                     .gid = getgid(),
                                     .mode = 0777,
                                     .atime = (uint32_t)current_time,
                                     .mtime = (uint32_t)current_time,
                                     .ctime = (uint32_t)current_time };
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

uint32_t entry_create_directory(const unsigned char *aes_key,
                                struct CryptFS_Entry_ID parent_dir_entry_id,
                                const char *name)
{
    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

        read_blocks_with_decryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry
                ->size--; // update size only at the end if succes of adding
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

    err_create_file_root:
        free(root_entry);
        return BLOCK_ERROR;
    }
    else
    {
        if (goto_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry =
            dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir);
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, dir);

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
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify
 * its metadata after adding entry)
 * @param name Name of the future hardlink.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param entry_to_link Entry to copy data from.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int
__entry_create_hardlink_routine(const unsigned char *aes_key,
                                struct CryptFS_Entry *entry, const char *name,
                                struct CryptFS_Entry_ID parent_dir_entry_id,
                                struct CryptFS_Entry entry_to_link)
{
    uint32_t index = 0;
    if (entry->type != ENTRY_TYPE_DIRECTORY)
        return BLOCK_ERROR;

    // Find free index in Directory
    struct CryptFS_Directory *parent_dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {
            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t)BLOCK_END)
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
    struct CryptFS_Entry new_hard = { .used = 1,
                                      .type = ENTRY_TYPE_HARDLINK,
                                      .start_block = entry_to_link.start_block,
                                      .size = entry_to_link.size,
                                      .uid = getuid(),
                                      .gid = getgid(),
                                      .mode = 0777,
                                      .atime = (uint32_t)current_time,
                                      .mtime = (uint32_t)current_time,
                                      .ctime = (uint32_t)current_time };
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

uint32_t entry_create_hardlink(const unsigned char *aes_key,
                               struct CryptFS_Entry_ID parent_dir_entry_id,
                               const char *name,
                               struct CryptFS_Entry_ID target_entry_id)
{
    uint32_t index;
    // Exctract entry to Link
    if (goto_entry_in_directory(aes_key, &target_entry_id))
        return BLOCK_ERROR;

    // allocate struct for reading target_link_block
    struct CryptFS_Directory *target_link_dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, target_entry_id.directory_block, 1,
                                    target_link_dir))
        goto err_create_file_init;

    struct CryptFS_Entry entry_to_link =
        target_link_dir->entries[target_entry_id.directory_index];

    // Test if the entry_to_link is a file
    if (entry_to_link.type != ENTRY_TYPE_FILE)
        goto err_create_file_init;

    if (parent_dir_entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

        read_blocks_with_decryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry
                ->size--; // update size only at the end if succes of adding
        }
        int res = __entry_create_hardlink_routine(
            aes_key, root_entry, name, parent_dir_entry_id, entry_to_link);
        if (res == BLOCK_ERROR)
        {
            if (initiated)
                entry_truncate(aes_key, parent_dir_entry_id, 0);
            goto err_create_file_root;
        }
        index = (uint32_t)res;

        // Update Entry
        root_entry->size++;
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

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
        if (goto_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;

        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        // Reading block
        if (read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Extract Entry
        struct CryptFS_Entry entry =
            dir->entries[parent_dir_entry_id.directory_index];

        // Check if it is effectively an Directory
        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;

        int initiated = 0; // if initiated still 0 =, directory didn't
                           // initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir);
            entry = dir->entries[parent_dir_entry_id.directory_index];
            entry.size--; // update size only at the end if succes of adding
            initiated = 1;
        }

        // Routine
        int res = __entry_create_hardlink_routine(
            aes_key, &entry, name, parent_dir_entry_id, entry_to_link);

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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, dir);

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
 * @param entry Pointer of the parent directory CryptFS_Entry. (Used to modify
 * its metadata after adding entry)
 * @param name Name of the future hardlink.
 * @param parent_dir_entry_id Structure, composed of the block number where a
 * struct CryptFS_Directory starts and the index of the entry within this
 * current CryptFS_Directory, serves to uniquely identify an entry on the file
 * system.
 * @param symlink Path to the linked entry.
 * @return 0 when success, BLOCK_ERROR otherwise.
 */
static int __entry_create_symlink_routine(
    const unsigned char *aes_key, struct CryptFS_Entry *entry, const char *name,
    struct CryptFS_Entry_ID parent_dir_entry_id, const char *symlink)
{
    uint32_t index = 0;

    // Find free index in Directory
    struct CryptFS_Directory *parent_dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    block_t s_block = entry->start_block;
    read_blocks_with_decryption(aes_key, s_block, 1, parent_dir);
    while (parent_dir->entries[index % NB_ENTRIES_PER_BLOCK].used != 0)
    {
        index++;
        if (index % NB_ENTRIES_PER_BLOCK == 0)
        {
            block_t tmp_block = read_fat_offset(aes_key, s_block);
            if (tmp_block == (uint32_t)BLOCK_END)
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
    struct CryptFS_Entry new_sym = { .used = 1,
                                     .type = ENTRY_TYPE_SYMLINK,
                                     .start_block = 0,
                                     .size = 0,
                                     .uid = getuid(),
                                     .gid = getgid(),
                                     .mode = 0777,
                                     .atime = (uint32_t)current_time,
                                     .mtime = (uint32_t)current_time,
                                     .ctime = (uint32_t)current_time };
    // Name
    strncpy(new_sym.name, name, ENTRY_NAME_MAX_LEN - 1);
    new_sym.name[ENTRY_NAME_MAX_LEN - 1] = '\0';
    parent_dir->entries[index % NB_ENTRIES_PER_BLOCK] = new_sym;

    // Write the block
    write_blocks_with_encryption(aes_key, s_block, 1, parent_dir);

    // Write symblink in file
    struct CryptFS_Entry_ID entry_id = { s_block,
                                         index % NB_ENTRIES_PER_BLOCK };
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

uint32_t entry_create_symlink(const unsigned char *aes_key,
                              struct CryptFS_Entry_ID parent_dir_entry_id,
                              const char *name, const char *symlink)
{
    if (!is_readable_ascii(symlink) || strlen(symlink) == 0)
        return BLOCK_ERROR;

    uint32_t index;

    if (parent_dir_entry_id.directory_block == ROOT_ENTRY_BLOCK)
    {
        // Allocate struct for reading directory_block
        struct CryptFS_Entry *root_entry = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

        read_blocks_with_decryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (root_entry->size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, root_entry);
            root_entry
                ->size--; // update size only at the end if succes of adding
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, root_entry);

        free(root_entry);
        return index;

    err_create_file_root:
        free(root_entry);
        return BLOCK_ERROR;
    }
    else
    {
        if (goto_entry_in_directory(aes_key, &parent_dir_entry_id))
            return BLOCK_ERROR;
        // allocate struct for reading directory_block
        struct CryptFS_Directory *dir = xaligned_alloc(
            CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

        if (read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir))
            goto err_create_file;

        // Get the parent_directory
        // Update Entry Directory
        struct CryptFS_Entry entry =
            dir->entries[parent_dir_entry_id.directory_index];

        if (entry.type != ENTRY_TYPE_DIRECTORY)
            goto err_create_file;
        int initiated =
            0; // if 0 = directory didn't initialized here, 1 if it init here
        if (entry.size == 0)
        {
            entry_truncate(aes_key, parent_dir_entry_id, 1);
            read_blocks_with_decryption(
                aes_key, parent_dir_entry_id.directory_block, 1, dir);
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
        write_blocks_with_encryption(
            aes_key, parent_dir_entry_id.directory_block, 1, dir);

        free(dir);
        return index;

    err_create_file:
        free(dir);
        return BLOCK_ERROR;
    }
}
