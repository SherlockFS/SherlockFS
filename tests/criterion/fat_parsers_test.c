#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "readfs.h"
#include "xalloc.h"

Test(find_first_free_block, out_of_band_available, .timeout = 10,
     .init = cr_redirect_stdout)
{
    set_device_path("build/tests/find_first_free_block.not_found.test.shlkfs");

    format_fs("build/tests/find_first_free_block.not_found.test.shlkfs",
              "build/tests/find_first_free_block.not_found.public.pem",
              "build/tests/find_first_free_block.not_found.private.pem", NULL,
              NULL);

    struct CryptFS_FAT first_fat = { 0 };
    for (unsigned i = 0; i < NB_FAT_ENTRIES_PER_BLOCK; i++)
        first_fat.entries[i].next_block = BLOCK_END;
    first_fat.next_fat_table = BLOCK_END;

    unsigned char *ase_key = extract_aes_key(
        "build/tests/find_first_free_block.not_found.test.shlkfs",
        "build/tests/find_first_free_block.not_found.private.pem");

    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1, &first_fat);

    int64_t result = find_first_free_block(ase_key);
    cr_assert_eq(result, -NB_FAT_ENTRIES_PER_BLOCK, "result = %ld", result);

    free(ase_key);

    // Removing the file after the test
    if (remove("build/tests/find_first_free_block.not_found.test.shlkfs") != 0)
        cr_assert_fail("Could not remove the file");
}

Test(find_first_free_block, on_first_fat, .timeout = 10,
     .init = cr_redirect_stdout)
{
    set_device_path(
        "build/tests/find_first_free_block.on_first_fat.test.shlkfs");

    format_fs("build/tests/find_first_free_block.on_first_fat.test.shlkfs",
              "build/tests/find_first_free_block.on_first_fat.public.pem",
              "build/tests/find_first_free_block.on_first_fat.private.pem",
              NULL, NULL);

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));
    memset(shlkfs->first_fat.entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));

    unsigned char *ase_key = extract_aes_key(
        "build/tests/find_first_free_block.on_first_fat.test.shlkfs",
        "build/tests/find_first_free_block.on_first_fat.private.pem");

    size_t index = 42;
    cr_assert(index < NB_FAT_ENTRIES_PER_BLOCK);

    shlkfs->first_fat.entries[index].next_block = BLOCK_FREE;
    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);

    int64_t result = find_first_free_block(ase_key);
    cr_assert_eq(result, index, "result = %ld", result);

    result = create_fat(ase_key);

    cr_assert_eq(result, index);

    free(ase_key);
    free(shlkfs);

    // Remove the file to avoid problems with other tests.
    if (remove("build/tests/find_first_free_block.on_first_fat.test.shlkfs")
        != 0)
        cr_assert_fail("Failed to remove the file.");
}

Test(find_first_free_block, on_second_fat, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path(
        "build/tests/find_first_free_block.on_second_fat.test.shlkfs");

    format_fs("build/tests/find_first_free_block.on_second_fat.test.shlkfs",
              "build/tests/find_first_free_block.on_second_fat.public.pem",
              "build/tests/find_first_free_block.on_second_fat.private.pem",
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

    // Filling second FAT
    memset(second_fat->entries, BLOCK_END,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    shlkfs->header.last_fat_block = ROOT_DIR_BLOCK + 2;
    second_fat->next_fat_table = BLOCK_END;

    size_t index = 42;
    second_fat->entries[index].next_block = BLOCK_FREE;

    // Reading the structure from the file
    unsigned char *ase_key = extract_aes_key(
        "build/tests/find_first_free_block.on_second_fat.test.shlkfs",
        "build/tests/find_first_free_block.on_second_fat.private.pem");

    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(ase_key, ROOT_DIR_BLOCK + 2, 1, second_fat);

    int64_t result = find_first_free_block(ase_key);
    cr_assert_eq(result, NB_FAT_ENTRIES_PER_BLOCK + index, "result = %ld",
                 result);

    result = create_fat(ase_key);

    cr_assert_eq(result, NB_FAT_ENTRIES_PER_BLOCK + index);

    free(ase_key);
    free(shlkfs);
}

Test(create_fat, two_fat_overflow_then_add_one_fat, .init = cr_redirect_stdout,
     .timeout = 10)
{
    // Setting the device and block size for read/write operations
    set_device_path("build/tests/create_fat.second_fat.test.shlkfs");

    format_fs("build/tests/create_fat.second_fat.test.shlkfs",
              "build/tests/create_fat.second_fat.public.pem",
              "build/tests/create_fat.second_fat.private.pem", NULL, NULL);

    // Reading the structure from the file
    unsigned char *ase_key =
        extract_aes_key("build/tests/create_fat.second_fat.test.shlkfs",
                        "build/tests/create_fat.second_fat.private.pem");

    int second_fat_index = create_fat(ase_key);
    cr_assert_eq(second_fat_index, ROOT_DIR_BLOCK + 2);

    struct CryptFS_FAT fat_full_1 = { 0 };
    memset(&fat_full_1, BLOCK_END, sizeof(fat_full_1));
    fat_full_1.next_fat_table = second_fat_index;

    struct CryptFS_FAT fat_full_2 = { 0 };
    memset(&fat_full_2, BLOCK_END, sizeof(fat_full_2));
    fat_full_2.next_fat_table = BLOCK_END;

    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1, &fat_full_1);
    write_blocks_with_encryption(ase_key, ROOT_DIR_BLOCK + 2, 1, &fat_full_2);

    int64_t result = find_first_free_block(ase_key);
    cr_assert_eq(result, -2 * NB_FAT_ENTRIES_PER_BLOCK, "result = %ld", result);

    result = create_fat(ase_key);

    cr_assert_eq(result, 2 * NB_FAT_ENTRIES_PER_BLOCK);
    // Deleting the file
    if (remove("build/tests/create_fat.second_fat.test.shlkfs") != 0)
        cr_assert(false, "Failed to remove the file");

    free(ase_key);
}

Test(create_fat, third_fat, .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));

    // Setting the device and block size for read/write operations
    set_device_path("build/tests/create_fat.third_fat.test.shlkfs");

    format_fs("build/tests/create_fat.third_fat.test.shlkfs",
              "build/tests/create_fat.third_fat.public.pem",
              "build/tests/create_fat.third_fat.private.pem", NULL, NULL);

    FILE *fp = fopen("build/tests/create_fat.third_fat.test.shlkfs", "r");
    if (fread(shlkfs, sizeof(struct CryptFS), 1, fp) != 1)
        cr_assert(false, "Failed to read the structure from a file");
    fclose(fp);

    // Reading the structure from the file
    unsigned char *ase_key =
        extract_aes_key("build/tests/create_fat.third_fat.test.shlkfs",
                        "build/tests/create_fat.third_fat.private.pem");
    int64_t result1 = create_fat(ase_key);
    int64_t result2 = create_fat(ase_key);

    cr_assert_eq(result1, ROOT_DIR_BLOCK + 2, "result1 = %ld", result1);
    cr_assert_eq(result2, ROOT_DIR_BLOCK + 3, "result2 = %ld", result2);

    // Deleting the file
    if (remove("build/tests/create_fat.third_fat.test.shlkfs") != 0)
        cr_assert(false, "Failed to remove the file");

    free(ase_key);
    free(shlkfs);
}
