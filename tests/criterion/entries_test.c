#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>
#include <signal.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "format.h"
#include "xalloc.h"
#include "entries.h"

#include <criterion/criterion.h>
#include <openssl/rand.h>
#include <string.h>

#include "entries.h"
#include "fat.h"
#include "block.h"
#include "xalloc.h"

// Test entry_truncate
Test(entry_truncate, file_add_blocks, .timeout = 10, 
    .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.file_add_blocks.test.shlkfs");

    format_fs("build/tests/entry_truncate.file_add_blocks.test.shlkfs",
              "build/tests/entry_truncate.file_add_blocks.public.pem",
              "build/tests/entry_truncate.file_add_blocks.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_add_blocks.test.shlkfs",
        "build/tests/entry_truncate.file_add_blocks.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 540,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 25000;

    // Check if function ended properly
    int result = entry_truncate(aes_key, dir_block, 0, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(read_fat_offset(aes_key,
     entry_block + __blocks_needed_for_file(resize_number) - 1), BLOCK_END);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].size, resize_number);
    
    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_truncate, file_remove_blocks, .timeout = 10, 
    .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.file_remove_blocks.test.shlkfs");

    format_fs("build/tests/entry_truncate.file_remove_blocks.test.shlkfs",
              "build/tests/entry_truncate.file_remove_blocks.public.pem",
              "build/tests/entry_truncate.file_remove_blocks.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_remove_blocks.test.shlkfs",
        "build/tests/entry_truncate.file_remove_blocks.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 540,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Adding blocks to the entry
    entry_truncate(aes_key, dir_block, 0, 25000);

    size_t resize_number = 4500;

    int result = entry_truncate(aes_key, dir_block, 0, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(read_fat_offset(aes_key,
     entry_block + __blocks_needed_for_file(resize_number) - 1), BLOCK_END);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].size, resize_number);
    
    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_truncate, file_remove_blocks_till_empty, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs");

    format_fs("build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs",
              "build/tests/entry_truncate.file_remove_blocks_to_empty.public.pem",
              "build/tests/entry_truncate.file_remove_blocks_to_empty.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs",
        "build/tests/entry_truncate.file_remove_blocks_to_empty.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 540,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 0;

    int result = entry_truncate(aes_key, dir_block, 0, resize_number);
    cr_assert_eq(result, 0);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].start_block, 0);
    cr_assert_eq(dir->entries[0].size, resize_number);
    
    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_truncate, directory_add_blocks, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.directory_add_blocks.test.shlkfs");

    format_fs("build/tests/entry_truncate.directory_add_blocks.test.shlkfs",
              "build/tests/entry_truncate.directory_add_blocks.public.pem",
              "build/tests/entry_truncate.directory_add_blocks.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.directory_add_blocks.test.shlkfs",
        "build/tests/entry_truncate.directory_add_blocks.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = entry_block,
        .name = "Dossier Vacances",
        .size = 12,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 28;

    // Check if function ended properly
    int result = entry_truncate(aes_key, dir_block, 0, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(read_fat_offset(aes_key,
     entry_block + __blocks_needed_for_dir(resize_number) - 1), BLOCK_END);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].size, resize_number);
    
    free(dir);
    free(aes_key);
    free(shlkfs);
}

// Test entry_write_buffer_from
Test(entry_write_buffer_from, begining_add, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_write_buffer_from.begining_add.test.shlkfs");

    format_fs("build/tests/entry_write_buffer_from.begining_add.test.shlkfs",
              "build/tests/entry_write_buffer_from.begining_add.public.pem",
              "build/tests/entry_write_buffer_from.begining_add.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_write_buffer_from.begining_add.test.shlkfs",
        "build/tests/entry_write_buffer_from.begining_add.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = 0,
        .name = "test_entry.txt",
        .size = 11,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // Initial Buffer
    char *block_buffer = 
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // TEST
    char* added_string = "This is a Test";
    int result = entry_write_buffer_from(aes_key, dir_block, 0, 
         0, added_string, strlen(added_string));
    cr_assert_eq(result, 0);

    // Read BLOCK result
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    read_blocks_with_decryption(aes_key, dir->entries[0].start_block, 1, block_buffer);
    result = memcmp(block_buffer, added_string, strlen(added_string));
    cr_assert_eq(result, 0);

    free(block_buffer);
    free(dir);
    free(aes_key);
    free(shlkfs);

}

Test(entry_write_buffer_from, between_blocks_adding, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_write_buffer_from.between_blocks_adding.test.shlkfs");

    format_fs("build/tests/entry_write_buffer_from.between_blocks_adding.test.shlkfs",
              "build/tests/entry_write_buffer_from.between_blocks_adding.public.pem",
              "build/tests/entry_write_buffer_from.between_blocks_adding.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_write_buffer_from.between_blocks_adding.test.shlkfs",
        "build/tests/entry_write_buffer_from.between_blocks_adding.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 0,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Initial Buffer
    char *block_buffer_1 = 
        xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    char *block_buffer_2 = 
        xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);

    // TEST
    char* added_string = "This is a Test";
    int result = entry_write_buffer_from(aes_key, dir_block, 0, 
         4090, added_string, strlen(added_string));
    cr_assert_eq(result, 0);

    // Read BLOCKS result
    read_blocks_with_decryption(aes_key, entry_block, 1, block_buffer_1);
    read_blocks_with_decryption(aes_key, read_fat_offset(aes_key, entry_block), 1, block_buffer_2);
    char* expected_string = "This i";
    result = memcmp(block_buffer_1 + 4090, expected_string, strlen(expected_string) - 1); // -1 to not include the '\0' char
    cr_assert_eq(result, 0);
    expected_string = "s a Test";
    result = memcmp(block_buffer_2, expected_string, strlen(expected_string));
    cr_assert_eq(result, 0);

    free(block_buffer_1);
    free(block_buffer_2);
    free(dir);
    free(aes_key);
    free(shlkfs);

}

// TEST entry_read_raw_data
Test(entry_read_raw_data, reading_between_blocks, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_write_buffer_from.reading_between_blocks.test.shlkfs");

    format_fs("build/tests/entry_write_buffer_from.reading_between_blocks.test.shlkfs",
              "build/tests/entry_write_buffer_from.reading_between_blocks.public.pem",
              "build/tests/entry_write_buffer_from.reading_between_blocks.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_write_buffer_from.reading_between_blocks.test.shlkfs",
        "build/tests/entry_write_buffer_from.reading_between_blocks.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 0,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Buffer to write
    char *buff = xmalloc(1, 5600);
    memset(buff, '6',5600);
    // Copy to verify at the end the buffer returned
    char *buff_2 = xmalloc(1, 5600);
    memset(buff_2, '6',5600);

    // Writing in file
    entry_write_buffer_from(aes_key, dir_block, 0, 2000, buff, 5600);
    
    // Reset buff and TEST
    memset(buff, '\0', 5600);
    cr_assert_eq(entry_read_raw_data(aes_key, dir_block, 0, 2000, buff, 5600), 5600);
    cr_assert_eq(memcmp(buff, buff_2, 5600), 0);

    free(buff);
    free(buff_2);
    free(dir);
    free(aes_key);
    free(shlkfs);

}

// TEST entry_delete
Test(entry_delete, file_and_directory, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_delete.file_and_directory.test.shlkfs");

    format_fs("build/tests/entry_delete.file_and_directory.test.shlkfs",
              "build/tests/entry_delete.file_and_directory.public.pem",
              "build/tests/entry_delete.file_and_directory.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_delete.file_and_directory.test.shlkfs",
        "build/tests/entry_delete.file_and_directory.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = entry_block,
        .name = "test_entry.txt",
        .size = 0,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Create an entry
    int64_t new_directory_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry new_dir = {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = new_directory_block,
        .name = "Dossier Vacances",
        .size = 2,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };
    write_fat_offset(aes_key, new_directory_block, BLOCK_END);

    // Put entries in Directory and Write in BLOCK
    dir->entries[0] = entry;
    dir->entries[1] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // Create 2 entries to put in the Parent directory "Dossier Vacances"
    int64_t test_file_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry test_file = {
        .used = 1,
        .type = ENTRY_TYPE_FILE,
        .start_block = test_file_block,
        .name = "flag.txt",
        .size = 4000,
        .uid = 1000,
        .gid = 1000,
        .mode = 0666,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };
    write_fat_offset(aes_key, test_file_block, BLOCK_END);

    int64_t test_dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry test_dir = {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = test_dir_block,
        .name = "flag.txt",
        .size = 20,
        .uid = 1000,
        .gid = 1000,
        .mode = 777,
        .atime = 0,
        .mtime = 0,
        .ctime = 0
    };
    write_fat_offset(aes_key, test_dir_block, BLOCK_END);

    dir->entries[0] = test_file;
    dir->entries[1] = test_dir;
    write_blocks_with_encryption(aes_key, new_directory_block, 1, dir);
    
    char *buff = xmalloc(1, 8900);
    memset(buff, '6',8900);

    // Write bytes in file
    entry_write_buffer_from(aes_key, dir_block, 0, 2000, buff, 8900);
    
    cr_assert_eq(entry_delete(aes_key, dir_block, 1, 0), 0);

    // check updated entry
    read_blocks_with_decryption(aes_key, new_directory_block, 1, dir);

    cr_assert_eq(dir->entries[0].start_block, 0);
    cr_assert_eq(dir->entries[0].size, 0);
    cr_assert_eq(dir->entries[0].used, 0);

    cr_assert_eq(entry_delete(aes_key, dir_block, 1, 1), -2);

    free(buff);
    free(dir);
    free(aes_key);
    free(shlkfs);
}

// TEST entry_create_empty_file
Test(entry_create_empty_file, in_one_block, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_empty_file.in_one_block.test.shlkfs");

    format_fs("build/tests/entry_create_empty_file.in_one_block.test.shlkfs",
              "build/tests/entry_create_empty_file.in_one_block.public.pem",
              "build/tests/entry_create_empty_file.in_one_block.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_empty_file.in_one_block.test.shlkfs",
        "build/tests/entry_create_empty_file.in_one_block.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = 0,
        .name = "Dossier Vacances",
        .size = 0,
        .uid = 1000,
        .gid = 1000,
        .mode = 777,
        .atime = 1,
        .mtime = 0,
        .ctime = 0
    };
    dir->entries[0]=new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // adding Files
    cr_assert_eq(entry_create_empty_file(aes_key, dir_block, 0, "Vacances"), 0);
    cr_assert_eq(entry_create_empty_file(aes_key, dir_block, 0, "Vacances2"), 1);
    cr_assert_eq(entry_create_empty_file(aes_key, dir_block, 0, "LALA"), 2);

    // Reading Parent Directory metadata
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    cr_assert_eq(dir->entries[0].size, 3);
    // Reading entries in Parent Directory
    read_blocks_with_decryption(aes_key, dir->entries[0].start_block, 1, dir);
    cr_assert_eq(dir->entries[0].used, 1);
    cr_assert_eq(dir->entries[0].used, 1);
    cr_assert_eq(dir->entries[0].used, 1);

    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_create_empty_file, in_multiple_blocks, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs");

    format_fs("build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs",
              "build/tests/entry_create_empty_file.in_multiple_blocks.public.pem",
              "build/tests/entry_create_empty_file.in_multiple_blocks.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs",
        "build/tests/entry_create_empty_file.in_multiple_blocks.private.pem");

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir =
        xaligned_alloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = {
        .used = 1,
        .type = ENTRY_TYPE_DIRECTORY,
        .start_block = 0,
        .name = "Dossier Vacances",
        .size = 0,
        .uid = 1000,
        .gid = 1000,
        .mode = 777,
        .atime = 1,
        .mtime = 0,
        .ctime = 0
    };
    dir->entries[0]=new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // adding Files to more than one block size directory
    size_t number_files = 26;
    for (size_t i = 0; i < number_files; i++)
    {
        cr_assert_eq(entry_create_empty_file(aes_key, dir_block, 0, "TEST"), i);
    }

    // Reading Parent Directory metadata
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    cr_assert_eq(dir->entries[0].size, number_files);
    // Reading entries in Parent Directory
    read_blocks_with_decryption(aes_key, dir->entries[0].start_block, 1, dir);
    for (size_t i = 0; i < number_files; i++)
    {
        if (i == NB_ENTRIES_PER_BLOCK)
        {
            // read next directory block
            read_blocks_with_decryption(aes_key, read_fat_offset(aes_key, dir->entries[0].start_block), 1, dir);
        }
        cr_assert_eq(dir->entries[i % NB_ENTRIES_PER_BLOCK].used, 1);   
    }
    

    free(dir);
    free(aes_key);
    free(shlkfs);
}