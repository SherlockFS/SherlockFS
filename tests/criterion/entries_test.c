#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>
#include <signal.h>
#include <string.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "entries.h"
#include "fat.h"
#include "format.h"
#include "fuse_ps_info.h"
#include "xalloc.h"

void cr_redirect_stdall(void);

// Test entry_truncate
Test(entry_truncate, file_add_blocks, .timeout = 10, .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_truncate.file_add_blocks.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path("build/tests/entry_truncate.file_add_blocks.test.shlkfs");

    format_fs("build/tests/entry_truncate.file_add_blocks.test.shlkfs",
              "build/tests/entry_truncate.file_add_blocks.public.pem",
              "build/tests/entry_truncate.file_add_blocks.private.pem", NULL,
              NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_add_blocks.test.shlkfs",
        "build/tests/entry_truncate.file_add_blocks.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 540,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 25000;

    // Check if function ended properly
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    int result = entry_truncate(aes_key, entry_id, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(
        read_fat_offset(
            aes_key, entry_block + __blocks_needed_for_file(resize_number) - 1),
        BLOCK_END);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].size, resize_number);

    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_truncate, file_remove_blocks, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_truncate.file_remove_blocks.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.file_remove_blocks.test.shlkfs");

    format_fs("build/tests/entry_truncate.file_remove_blocks.test.shlkfs",
              "build/tests/entry_truncate.file_remove_blocks.public.pem",
              "build/tests/entry_truncate.file_remove_blocks.private.pem", NULL,
              NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_remove_blocks.test.shlkfs",
        "build/tests/entry_truncate.file_remove_blocks.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 540,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Adding blocks to the entry
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    entry_truncate(aes_key, entry_id, 25000);

    size_t resize_number = 4500;

    int result = entry_truncate(aes_key, entry_id, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(
        read_fat_offset(
            aes_key, entry_block + __blocks_needed_for_file(resize_number) - 1),
        BLOCK_END);

    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    cr_assert_eq(dir->entries[0].size, resize_number);

    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_truncate, file_remove_blocks_till_empty, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system(
        "dd if=/dev/zero "
        "of=build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs "
        "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs");

    format_fs(
        "build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs",
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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.file_remove_blocks_to_empty.test.shlkfs",
        "build/tests/entry_truncate.file_remove_blocks_to_empty.private.pem",
        NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 540,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 0;

    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    int result = entry_truncate(aes_key, entry_id, resize_number);
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
    system("dd if=/dev/zero "
           "of=build/tests/entry_truncate.directory_add_blocks.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_truncate.directory_add_blocks.test.shlkfs",
        "build/tests/entry_truncate.directory_add_blocks.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_DIRECTORY,
                                   .start_block = entry_block,
                                   .name = "Dossier Vacances",
                                   .size = 12,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    size_t resize_number = 28;

    // Check if function ended properly
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    int result = entry_truncate(aes_key, entry_id, resize_number);
    cr_assert_eq(result, 0);

    cr_assert_eq(
        read_fat_offset(
            aes_key, entry_block + __blocks_needed_for_dir(resize_number) - 1),
        BLOCK_END);

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
    system("dd if=/dev/zero "
           "of=build/tests/entry_write_buffer_from.begining_add.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_write_buffer_from.begining_add.test.shlkfs",
        "build/tests/entry_write_buffer_from.begining_add.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = 0,
                                   .name = "test_entry.txt",
                                   .size = 11,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // Initial Buffer
    char *block_buffer =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // TEST
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    char *added_string = "This is a Test";
    int result = entry_write_buffer_from(aes_key, entry_id, 0, added_string,
                                         strlen(added_string));
    cr_assert_eq(result, 0);

    // Read BLOCK result
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    read_blocks_with_decryption(aes_key, dir->entries[0].start_block, 1,
                                block_buffer);
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
    system("dd if=/dev/zero "
           "of=build/tests/"
           "entry_write_buffer_from.between_blocks_adding.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/"
        "entry_write_buffer_from.between_blocks_adding.test.shlkfs");

    format_fs(
        "build/tests/entry_write_buffer_from.between_blocks_adding.test.shlkfs",
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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_write_buffer_from.between_blocks_adding.test.shlkfs",
        "build/tests/"
        "entry_write_buffer_from.between_blocks_adding.private.pem",
        NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 0,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Initial Buffer
    char *block_buffer_1 = xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    char *block_buffer_2 = xmalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);

    // TEST
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    char *added_string = "This is a Test";
    int result = entry_write_buffer_from(aes_key, entry_id, 4090, added_string,
                                         strlen(added_string));
    cr_assert_eq(result, 0);

    // Read BLOCKS result
    read_blocks_with_decryption(aes_key, entry_block, 1, block_buffer_1);
    read_blocks_with_decryption(aes_key, read_fat_offset(aes_key, entry_block),
                                1, block_buffer_2);
    char *expected_string = "This i";
    result =
        memcmp(block_buffer_1 + 4090, expected_string,
               strlen(expected_string) - 1); // -1 to not include the '\0' char
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
    system("dd if=/dev/zero "
           "of=build/tests/"
           "entry_write_buffer_from.reading_between_blocks.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/"
        "entry_write_buffer_from.reading_between_blocks.test.shlkfs");

    format_fs(
        "build/tests/"
        "entry_write_buffer_from.reading_between_blocks.test.shlkfs",
        "build/tests/entry_write_buffer_from.reading_between_blocks.public.pem",
        "build/tests/"
        "entry_write_buffer_from.reading_between_blocks.private.pem",
        NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/"
        "entry_write_buffer_from.reading_between_blocks.test.shlkfs",
        "build/tests/"
        "entry_write_buffer_from.reading_between_blocks.private.pem",
        NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 0,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };

    // Write Directory in BLOCK and update FAT
    dir->entries[0] = entry;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Buffer to write
    char *buff = xmalloc(1, 5600);
    memset(buff, '6', 5600);
    // Copy to verify at the end the buffer returned
    char *buff_2 = xmalloc(1, 5600);
    memset(buff_2, '6', 5600);

    // Writing in file
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    entry_write_buffer_from(aes_key, entry_id, 2000, buff, 5600);

    // Reset buff and TEST
    memset(buff, '\0', 5600);
    cr_assert_eq(entry_read_raw_data(aes_key, entry_id, 2000, buff, 5600),
                 5600);
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
    system("dd if=/dev/zero "
           "of=build/tests/entry_delete.file_and_directory.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path("build/tests/entry_delete.file_and_directory.test.shlkfs");

    format_fs("build/tests/entry_delete.file_and_directory.test.shlkfs",
              "build/tests/entry_delete.file_and_directory.public.pem",
              "build/tests/entry_delete.file_and_directory.private.pem", NULL,
              NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_delete.file_and_directory.test.shlkfs",
        "build/tests/entry_delete.file_and_directory.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    int64_t entry_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry entry = { .used = 1,
                                   .type = ENTRY_TYPE_FILE,
                                   .start_block = entry_block,
                                   .name = "test_entry.txt",
                                   .size = 0,
                                   .uid = 1000,
                                   .gid = 1000,
                                   .mode = 0666,
                                   .atime = 0,
                                   .mtime = 0,
                                   .ctime = 0 };
    write_fat_offset(aes_key, entry_block, BLOCK_END);

    // Create an entry
    int64_t new_directory_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = new_directory_block,
                                     .name = "Dossier Vacances",
                                     .size = 2,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0666,
                                     .atime = 0,
                                     .mtime = 0,
                                     .ctime = 0 };
    write_fat_offset(aes_key, new_directory_block, BLOCK_END);

    // Put entries in Directory and Write in BLOCK
    dir->entries[0] = entry;
    dir->entries[1] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // Create 2 entries to put in the Parent directory "Dossier Vacances"
    int64_t test_file_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry test_file = { .used = 1,
                                       .type = ENTRY_TYPE_FILE,
                                       .start_block = test_file_block,
                                       .name = "flag.txt",
                                       .size = 4000,
                                       .uid = 1000,
                                       .gid = 1000,
                                       .mode = 0666,
                                       .atime = 0,
                                       .mtime = 0,
                                       .ctime = 0 };
    write_fat_offset(aes_key, test_file_block, BLOCK_END);

    int64_t test_dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Entry test_dir = { .used = 1,
                                      .type = ENTRY_TYPE_DIRECTORY,
                                      .start_block = test_dir_block,
                                      .name = "flag.txt",
                                      .size = 20,
                                      .uid = 1000,
                                      .gid = 1000,
                                      .mode = 0777,
                                      .atime = 0,
                                      .mtime = 0,
                                      .ctime = 0 };
    write_fat_offset(aes_key, test_dir_block, BLOCK_END);

    dir->entries[0] = test_file;
    dir->entries[1] = test_dir;
    write_blocks_with_encryption(aes_key, new_directory_block, 1, dir);

    char *buff = xmalloc(1, 8900);
    memset(buff, '6', 8900);

    // Write bytes in file
    struct CryptFS_Entry_ID first_file_entry_id = { dir_block, 0 };
    entry_write_buffer_from(aes_key, first_file_entry_id, 2000, buff, 8900);

    struct CryptFS_Entry_ID second_dir_entry_id = { dir_block, 1 };
    cr_assert_eq(entry_delete(aes_key, second_dir_entry_id, 0), 0);

    // check updated entry
    read_blocks_with_decryption(aes_key, new_directory_block, 1, dir);

    cr_assert_eq(dir->entries[0].start_block, 0);
    cr_assert_eq(dir->entries[0].size, 0);
    cr_assert_eq(dir->entries[0].used, 0);

    cr_assert_eq(entry_delete(aes_key, second_dir_entry_id, 1), -2);

    free(buff);
    free(dir);
    free(aes_key);
    free(shlkfs);
}

// TEST entry_create_empty_file
Test(entry_create_empty_file, in_one_block, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_create_empty_file.in_one_block.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_empty_file.in_one_block.test.shlkfs",
        "build/tests/entry_create_empty_file.in_one_block.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "Dossier Vacances",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    // adding Files
    cr_assert_eq(entry_create_empty_file(aes_key, entry_id, "Vacances"), 0);
    cr_assert_eq(entry_create_empty_file(aes_key, entry_id, "Vacances2"), 1);
    cr_assert_eq(entry_create_empty_file(aes_key, entry_id, "LALA"), 2);

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
    system(
        "dd if=/dev/zero "
        "of=build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs "
        "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs");

    format_fs(
        "build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs",
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
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_empty_file.in_multiple_blocks.test.shlkfs",
        "build/tests/entry_create_empty_file.in_multiple_blocks.private.pem",
        NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "Dossier Vacances",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    // adding Files to more than one block size directory
    size_t number_files = 26;
    for (size_t i = 0; i < number_files; i++)
    {
        cr_assert_eq(entry_create_empty_file(aes_key, entry_id, "TEST"), i);
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
            if (read_fat_offset(aes_key, dir->entries[0].start_block)
                != (u_int32_t)BLOCK_END)
                read_blocks_with_decryption(
                    aes_key,
                    read_fat_offset(aes_key, dir->entries[0].start_block), 1,
                    dir);
        }
        cr_assert_eq(dir->entries[i % NB_ENTRIES_PER_BLOCK].used, 1);
    }

    free(dir);
    free(aes_key);
    free(shlkfs);
}

// TEST entry_create_directory
Test(entry_create_directory, embedded_directories, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/"
           "entry_create_directory.embedded_directories.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_directory.embedded_directories.test.shlkfs");

    format_fs(
        "build/tests/entry_create_directory.embedded_directories.test.shlkfs",
        "build/tests/entry_create_directory.embedded_directories.public.pem",
        "build/tests/entry_create_directory.embedded_directories.private.pem",
        NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_directory.embedded_directories.test.shlkfs",
        "build/tests/entry_create_directory.embedded_directories.private.pem",
        NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "Dossier Vacances",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };

    // adding Directory in Dossier Vacances
    cr_assert_eq(entry_create_directory(aes_key, entry_id, "Dossier Secret"),
                 0);

    // Update Dossier Vacances metadata
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    block_t start_dossier_vac_block = dir->entries[0].start_block;

    struct CryptFS_Entry_ID vac_entry_id = { start_dossier_vac_block, 0 };
    // adding directory in the Dossier Secret
    cr_assert_eq(entry_create_directory(aes_key, vac_entry_id, "Treees Secret"),
                 0);

    // Update Dossier Secret metadata
    read_blocks_with_decryption(aes_key, start_dossier_vac_block, 1, dir);
    block_t start_dossier_sec_block = dir->entries[0].start_block;

    // Verify DOSSIER SECRET data
    cr_assert_eq(dir->entries[0].size, 1);
    cr_assert_eq(dir->entries[0].used, 1);
    cr_assert_neq(dir->entries[0].start_block, 0);
    cr_assert_str_eq(dir->entries[0].name, "Dossier Secret");

    // Verify TREEEES SECRET data
    read_blocks_with_decryption(aes_key, start_dossier_sec_block, 1, dir);
    cr_assert_eq(dir->entries[0].size, 0);
    cr_assert_eq(dir->entries[0].used, 1);
    cr_assert_eq(dir->entries[0].start_block, 0);
    cr_assert_str_eq(dir->entries[0].name, "Treees Secret");

    free(dir);
    free(aes_key);
    free(shlkfs);
}

// TEST entry_create_hardlink
Test(entry_create_hardlink, simple_hardlink, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_create_hardlink.simple_hardlink.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_hardlink.simple_hardlink.test.shlkfs");

    format_fs("build/tests/entry_create_hardlink.simple_hardlink.test.shlkfs",
              "build/tests/entry_create_hardlink.simple_hardlink.public.pem",
              "build/tests/entry_create_hardlink.simple_hardlink.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_hardlink.simple_hardlink.test.shlkfs",
        "build/tests/entry_create_hardlink.simple_hardlink.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "TEST",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    // adding Original File in TEST directory placed in dir_block[0]
    entry_create_empty_file(aes_key, entry_id, "Original");
    // Update dir_block
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    // Write into it
    size_t size = 17; // Eroor asan if > real size
    char *content = "Testing Hardlink";
    struct CryptFS_Entry_ID file_entry_id = { dir->entries[0].start_block, 0 };
    entry_write_buffer(aes_key, file_entry_id, content, size);

    // Update dir_block
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    // Creating Hardlink
    uint32_t res = entry_create_hardlink(aes_key, entry_id,
                                         "Hardlink_to_Original", file_entry_id);

    // Check TEST directory metadata
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    struct CryptFS_Entry TEST_entry = dir->entries[0];
    cr_assert_eq(TEST_entry.size, 2);

    // Check Hardlink
    read_blocks_with_decryption(aes_key, TEST_entry.start_block, 1, dir);
    struct CryptFS_Entry Original_entry = dir->entries[0];
    struct CryptFS_Entry Hardlink_entry = dir->entries[1];
    cr_assert_eq(Hardlink_entry.type, ENTRY_TYPE_HARDLINK);
    cr_assert_str_eq(Hardlink_entry.name, "Hardlink_to_Original");
    cr_assert_eq(Hardlink_entry.start_block, Original_entry.start_block);
    cr_assert_eq(Hardlink_entry.size, Original_entry.size);
    struct CryptFS_Entry_ID file_original_entry_id = { TEST_entry.start_block,
                                                       0 };
    struct CryptFS_Entry_ID file_hard_entry_id = { TEST_entry.start_block, 1 };
    // buff
    char *buff1 = malloc(size);
    char *buff2 = malloc(size);
    entry_read_raw_data(aes_key, file_original_entry_id, 0, buff1, size);
    entry_read_raw_data(aes_key, file_hard_entry_id, 0, buff2, size);
    cr_assert_str_eq(buff1, buff2);
    cr_assert_eq(res, 1);

    free(buff1);
    free(buff2);
    free(dir);
    free(aes_key);
    free(shlkfs);
}

// TEST entry_create_symlink
Test(entry_create_symlink, simple_symlink, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_create_symlink.simple_symlink.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_symlink.simple_symlink.test.shlkfs");

    format_fs("build/tests/entry_create_symlink.simple_symlink.test.shlkfs",
              "build/tests/entry_create_symlink.simple_symlink.public.pem",
              "build/tests/entry_create_symlink.simple_symlink.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_symlink.simple_symlink.test.shlkfs",
        "build/tests/entry_create_symlink.simple_symlink.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "TEST",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // adding symlink
    char *path = "/usr/bin/shlkfs";
    char *name = "Symlink_test";
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    uint32_t res = entry_create_symlink(aes_key, entry_id, name, path);

    // Update dir_block
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);

    // Check TEST directory metadata
    read_blocks_with_decryption(aes_key, dir_block, 1, dir);
    struct CryptFS_Entry TEST_entry = dir->entries[0];
    cr_assert_eq(TEST_entry.size, 1);

    // Check Symlink
    read_blocks_with_decryption(aes_key, TEST_entry.start_block, 1, dir);
    struct CryptFS_Entry Symlink_entry = dir->entries[0];
    cr_assert_eq(Symlink_entry.type, ENTRY_TYPE_SYMLINK);
    cr_assert_str_eq(Symlink_entry.name, name);
    cr_assert_neq(Symlink_entry.start_block, 0);
    cr_assert_eq(Symlink_entry.size, strlen(path));
    struct CryptFS_Entry_ID file_entry_id = { TEST_entry.start_block, 0 };
    // buff
    char *buff1 = malloc(strlen(path));
    entry_read_raw_data(aes_key, file_entry_id, 0, buff1, strlen(path));
    cr_assert_eq(res, 0);

    free(buff1);
    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(entry_create_symlink, bad_path_ascii, .timeout = 10,
     .init = cr_redirect_stdout)
{
    system("dd if=/dev/zero "
           "of=build/tests/entry_create_symlink.bad_path_ascii.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/entry_create_symlink.bad_path_ascii.test.shlkfs");

    format_fs("build/tests/entry_create_symlink.bad_path_ascii.test.shlkfs",
              "build/tests/entry_create_symlink.bad_path_ascii.public.pem",
              "build/tests/entry_create_symlink.bad_path_ascii.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1,
                        sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)shlkfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->first_fat.next_fat_table = ROOT_ENTRY_BLOCK + 2;

    // Reading the structure from the file
    unsigned char *aes_key = extract_aes_key(
        "build/tests/entry_create_symlink.bad_path_ascii.test.shlkfs",
        "build/tests/entry_create_symlink.bad_path_ascii.private.pem", NULL);

    write_blocks_with_encryption(aes_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(aes_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(aes_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(aes_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "TEST",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 0777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(aes_key, dir_block, 1, dir);

    // adding symlink
    char *path = "/usr/bin$*!你好@(#_++=/shlkfs";
    char *name = "Symlink_test";
    struct CryptFS_Entry_ID entry_id = { dir_block, 0 };
    uint32_t res = entry_create_symlink(aes_key, entry_id, name, path);

    cr_assert_eq(res, BLOCK_ERROR);

    free(dir);
    free(aes_key);
    free(shlkfs);
}

Test(get_entry_by_path, root, .init = cr_redirect_stdall, .timeout = 10)
{
    system("dd if=/dev/zero of=build/get_entry_by_path.root.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.root.test.shlkfs");

    format_fs("build/get_entry_by_path.root.test.shlkfs",
              "build/get_entry_by_path.root.public.pem",
              "build/get_entry_by_path.root.private.pem", NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.root.test.shlkfs",
        "build/get_entry_by_path.root.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    free(entry_id);
}

Test(get_entry_by_path, not_existing, .init = cr_redirect_stdall, .timeout = 10)
{
    system(
        "dd if=/dev/zero of=build/get_entry_by_path.not_existing.test.shlkfs "
        "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.not_existing.test.shlkfs");

    format_fs("build/get_entry_by_path.not_existing.test.shlkfs",
              "build/get_entry_by_path.not_existing.public.pem",
              "build/get_entry_by_path.not_existing.private.pem", NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.not_existing.test.shlkfs",
        "build/get_entry_by_path.not_existing.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/not_existing");

    cr_assert_eq(entry_id, BLOCK_NOT_SUCH_ENTRY);
}

Test(get_entry_by_path, not_existing_ending_slash, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.not_existing_ending_slash.test.shlkfs "
           "bs=4096 count=100");

    set_device_path(
        "build/get_entry_by_path.not_existing_ending_slash.test.shlkfs");

    format_fs("build/get_entry_by_path.not_existing_ending_slash.test.shlkfs",
              "build/get_entry_by_path.not_existing_ending_slash.public.pem",
              "build/get_entry_by_path.not_existing_ending_slash.private.pem",
              NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.not_existing_ending_slash.test.shlkfs",
        "build/get_entry_by_path.not_existing_ending_slash.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/not_existing/");

    cr_assert_eq(entry_id, BLOCK_NOT_SUCH_ENTRY);
}

Test(get_entry_by_path, create_single_file, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.create_single_file.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.create_single_file.test.shlkfs");

    format_fs("build/get_entry_by_path.create_single_file.test.shlkfs",
              "build/get_entry_by_path.create_single_file.public.pem",
              "build/get_entry_by_path.create_single_file.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_single_file.test.shlkfs",
        "build/get_entry_by_path.create_single_file.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id, "test_file");

    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_file");

    cr_assert_neq(entry_id_test_file, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_file->directory_block, ROOT_DIR_BLOCK,
                 "entry_id_test_file->directory_block: %ld",
                 entry_id_test_file->directory_block);
    cr_assert_eq(entry_id_test_file->directory_index, 0);

    free(entry_id);
    free(entry_id_test_file);
}

Test(get_entry_by_path, create_two_file, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.create_two_file.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.create_two_file.test.shlkfs");

    format_fs("build/get_entry_by_path.create_two_file.test.shlkfs",
              "build/get_entry_by_path.create_two_file.public.pem",
              "build/get_entry_by_path.create_two_file.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_two_file.test.shlkfs",
        "build/get_entry_by_path.create_two_file.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id, "test_file");
    entry_create_empty_file(fpi_get_master_key(), *entry_id, "test_file2");

    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_file");

    cr_assert_neq(entry_id_test_file, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_file->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_file->directory_index, 0);

    struct CryptFS_Entry_ID *entry_id_test_file2 =
        get_entry_by_path(fpi_get_master_key(), "/test_file2");

    cr_assert_neq(entry_id_test_file2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_file2->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_file2->directory_index, 1);

    free(entry_id);
    free(entry_id_test_file);
    free(entry_id_test_file2);
}

Test(get_entry_by_path, create_one_file_one_non_existing,
     .init = cr_redirect_stdall, .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/"
           "get_entry_by_path.create_one_file_one_non_existing.test.shlkfs "
           "bs=4096 count=100");

    set_device_path(
        "build/get_entry_by_path.create_one_file_one_non_existing.test.shlkfs");

    format_fs(
        "build/get_entry_by_path.create_one_file_one_non_existing.test.shlkfs",
        "build/get_entry_by_path.create_one_file_one_non_existing.public.pem",
        "build/get_entry_by_path.create_one_file_one_non_existing.private.pem",
        NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_one_file_one_non_existing.test.shlkfs",
        "build/get_entry_by_path.create_one_file_one_non_existing.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id, "test_file");

    struct CryptFS_Entry_ID *entry_id_non_existing =
        get_entry_by_path(fpi_get_master_key(), "/non_existing");

    cr_assert_eq(entry_id_non_existing, BLOCK_NOT_SUCH_ENTRY);

    free(entry_id);
}

Test(get_entry_by_path, create_one_directory, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.create_one_directory.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.create_one_directory.test.shlkfs");

    format_fs("build/get_entry_by_path.create_one_directory.test.shlkfs",
              "build/get_entry_by_path.create_one_directory.public.pem",
              "build/get_entry_by_path.create_one_directory.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_one_directory.test.shlkfs",
        "build/get_entry_by_path.create_one_directory.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    free(entry_id);
    free(entry_id_test_directory);
}

Test(get_entry_by_path, create_one_directory_ending_slash,
     .init = cr_redirect_stdall, .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/"
           "get_entry_by_path.create_one_directory_ending_slash.test.shlkfs "
           "bs=4096 count=100");

    set_device_path(
        "build/"
        "get_entry_by_path.create_one_directory_ending_slash.test.shlkfs");

    format_fs(
        "build/get_entry_by_path.create_one_directory_ending_slash.test.shlkfs",
        "build/get_entry_by_path.create_one_directory_ending_slash.public.pem",
        "build/get_entry_by_path.create_one_directory_ending_slash.private.pem",
        NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_one_directory_ending_slash.test.shlkfs",
        "build/"
        "get_entry_by_path.create_one_directory_ending_slash.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    free(entry_id);
    free(entry_id_test_directory);
}

Test(get_entry_by_path, create_two_directory, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.create_two_directory.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.create_two_directory.test.shlkfs");

    format_fs("build/get_entry_by_path.create_two_directory.test.shlkfs",
              "build/get_entry_by_path.create_two_directory.public.pem",
              "build/get_entry_by_path.create_two_directory.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.create_two_directory.test.shlkfs",
        "build/get_entry_by_path.create_two_directory.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");
    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory2");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    struct CryptFS_Entry_ID *entry_id_test_directory2 =
        get_entry_by_path(fpi_get_master_key(), "/test_directory2");

    cr_assert_neq(entry_id_test_directory2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory2->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory2->directory_index, 1);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_directory2);
}

Test(get_entry_by_path, one_file_in_one_dir, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.one_file_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.one_file_in_one_dir.test.shlkfs");

    format_fs("build/get_entry_by_path.one_file_in_one_dir.test.shlkfs",
              "build/get_entry_by_path.one_file_in_one_dir.public.pem",
              "build/get_entry_by_path.one_file_in_one_dir.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.one_file_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.one_file_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file");

    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);
    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file");

    cr_assert_neq(entry_id_test_file, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(
        entry_id_test_file->directory_block, test_directory->start_block,
        "entry_id_test_file->directory_block: %ld, "
        "test_directory->start_block: %ld",
        entry_id_test_file->directory_block, test_directory->start_block);
    cr_assert_eq(entry_id_test_file->directory_index, 0);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_file);
}

Test(get_entry_by_path, two_file_in_one_dir, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.two_file_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.two_file_in_one_dir.test.shlkfs");

    format_fs("build/get_entry_by_path.two_file_in_one_dir.test.shlkfs",
              "build/get_entry_by_path.two_file_in_one_dir.public.pem",
              "build/get_entry_by_path.two_file_in_one_dir.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.two_file_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.two_file_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file");
    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file2");

    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);
    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file");

    cr_assert_neq(entry_id_test_file, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_file->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_file->directory_index, 0);

    struct CryptFS_Entry_ID *entry_id_test_file2 =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file2");

    cr_assert_neq(entry_id_test_file2, BLOCK_NOT_SUCH_ENTRY);
}

Test(get_entry_by_path, one_dir_in_one_dir, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.one_dir_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.one_dir_in_one_dir.test.shlkfs");

    format_fs("build/get_entry_by_path.one_dir_in_one_dir.test.shlkfs",
              "build/get_entry_by_path.one_dir_in_one_dir.public.pem",
              "build/get_entry_by_path.one_dir_in_one_dir.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.one_dir_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.one_dir_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id_test_directory,
                           "test_directory2");
    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);

    struct CryptFS_Entry_ID *entry_id_test_directory2 = get_entry_by_path(
        fpi_get_master_key(), "/test_directory/test_directory2");

    cr_assert_neq(entry_id_test_directory2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory2->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_directory2->directory_index, 0);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_directory2);
}

Test(get_entry_by_path, one_dir_in_one_dir_ending_slash,
     .init = cr_redirect_stdall, .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.one_dir_in_one_dir_ending_slash.test."
           "shlkfs "
           "bs=4096 count=100");

    set_device_path(
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.test.shlkfs");

    format_fs(
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.test.shlkfs",
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.public.pem",
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.private.pem",
        NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.test.shlkfs",
        "build/get_entry_by_path.one_dir_in_one_dir_ending_slash.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id_test_directory,
                           "test_directory2");
    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);

    struct CryptFS_Entry_ID *entry_id_test_directory2 = get_entry_by_path(
        fpi_get_master_key(), "/test_directory/test_directory2/");

    cr_assert_neq(entry_id_test_directory2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory2->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_directory2->directory_index, 0);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_directory2);
}

Test(get_entry_by_path, two_dir_in_one_dir, .init = cr_redirect_stdall,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/get_entry_by_path.two_dir_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("build/get_entry_by_path.two_dir_in_one_dir.test.shlkfs");

    format_fs("build/get_entry_by_path.two_dir_in_one_dir.test.shlkfs",
              "build/get_entry_by_path.two_dir_in_one_dir.public.pem",
              "build/get_entry_by_path.two_dir_in_one_dir.private.pem", NULL,
              NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.two_dir_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.two_dir_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

        entry_create_directory(fpi_get_master_key(), *entry_id_test_directory,
                           "test_directory2");
    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);

    struct CryptFS_Entry_ID *entry_id_test_directory2 = get_entry_by_path(
        fpi_get_master_key(), "/test_directory/test_directory2");

    cr_assert_neq(entry_id_test_directory2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory2->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_directory2->directory_index, 0);

    // Create a third directory /test_directory/test_directory3
    entry_create_directory(fpi_get_master_key(), *entry_id_test_directory,
                           "test_directory3");

    struct CryptFS_Entry_ID *entry_id_test_directory3 = get_entry_by_path(
        fpi_get_master_key(), "/test_directory/test_directory3");

    cr_assert_neq(entry_id_test_directory3, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory3->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_directory3->directory_index, 1);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_directory2);
    free(entry_id_test_directory3);
}

Test(get_entry_by_path, one_file_and_one_dir_in_one_dir,
     .init = cr_redirect_stdall, .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/"
           "get_entry_by_path.one_file_and_one_dir_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path(
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.test.shlkfs");

    format_fs(
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.public.pem",
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.private.pem",
        NULL, NULL);

    fpi_register_master_key_from_path(
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.test.shlkfs",
        "build/get_entry_by_path.one_file_and_one_dir_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    cr_assert_eq(entry_id->directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(entry_id->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    cr_assert_neq(entry_id_test_directory, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory->directory_block, ROOT_DIR_BLOCK);
    cr_assert_eq(entry_id_test_directory->directory_index, 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file");

    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);

    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file");

    cr_assert_neq(entry_id_test_file, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_file->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_file->directory_index, 0);

    entry_create_directory(fpi_get_master_key(), *entry_id_test_directory,
                           "test_directory2");

    struct CryptFS_Entry_ID *entry_id_test_directory2 = get_entry_by_path(
        fpi_get_master_key(), "/test_directory/test_directory2");
    
    cr_assert_neq(entry_id_test_directory2, BLOCK_NOT_SUCH_ENTRY);
    cr_assert_eq(entry_id_test_directory2->directory_block,
                 test_directory->start_block);
    cr_assert_eq(entry_id_test_directory2->directory_index, 1);

    free(entry_id);
    free(entry_id_test_directory);
    free(entry_id_test_file);
}
