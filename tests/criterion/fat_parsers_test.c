#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "block.h"
#include "cryptfs.h"
#include "fat.h"
#include "format.h"
#include "xalloc.h"

Test(find_first_free_block, not_found, .timeout = 10,
     .init = cr_redirect_stdout)
{
    set_device_path("build/tests/find_first_free_block.not_found.test.cfs");

    format_fs("build/tests/find_first_free_block.not_found.test.cfs",
              "build/tests/find_first_free_block.not_found.public.pem",
              "build/tests/find_first_free_block.not_found.private.pem", NULL,
              NULL);

    struct CryptFS_FAT *first_fat = xaligned_alloc(
        sizeof(struct CryptFS_FAT), 1, sizeof(struct CryptFS_FAT));
    memset(first_fat->entries, 0xDEAD,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    first_fat->next_fat_table = FAT_BLOCK_END;
    write_blocks(FIRST_FAT_BLOCK, 1, first_fat);

    int64_t result = find_first_free_block(first_fat);
    cr_assert_eq(result, -1, "result = %ld", result);

    free(first_fat);

    // Removing the file after the test
    if (remove("build/tests/find_first_free_block.not_found.test.cfs") != 0)
        cr_assert_fail("Could not remove the file");
}

Test(find_first_free_block, on_first_fat, .timeout = 10,
     .init = cr_redirect_stdout)
{
    set_device_path("build/tests/find_first_free_block.on_first_fat.test.cfs");

    format_fs("build/tests/find_first_free_block.on_first_fat.test.cfs",
              "build/tests/find_first_free_block.on_first_fat.public.pem",
              "build/tests/find_first_free_block.on_first_fat.private.pem",
              NULL, NULL);

    struct CryptFS *cfs = xcalloc(1, sizeof(struct CryptFS));
    memset(cfs->first_fat.entries, 0xDEAD,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));

    size_t index = 42;
    cr_assert(index < NB_FAT_ENTRIES_PER_BLOCK);

    cfs->first_fat.entries[index].next_block = FAT_BLOCK_FREE;
    write_blocks(FIRST_FAT_BLOCK, 1, &cfs->first_fat);

    int64_t result = find_first_free_block(&cfs->first_fat);
    cr_assert_eq(result, index, "result = %ld", result);

    free(cfs);

    // Remove the file to avoid problems with other tests.
    if (remove("build/tests/find_first_free_block.on_first_fat.test.cfs") != 0)
        cr_assert_fail("Failed to remove the file.");
}

Test(find_first_free_block, on_second_fat, .timeout = 10,
     .init = cr_redirect_stdout)
{
    // Setting the device and block size for read/write operations
    set_device_path("build/tests/find_first_free_block.on_second_fat.test.cfs");

    format_fs("build/tests/find_first_free_block.on_second_fat.test.cfs",
              "build/tests/find_first_free_block.on_second_fat.public.pem",
              "build/tests/find_first_free_block.on_second_fat.private.pem",
              NULL, NULL);

    struct CryptFS *cfs =
        xcalloc(1, sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat =
        (struct CryptFS_FAT *)((char *)cfs + sizeof(struct CryptFS));

    // Filling first FAT
    memset(cfs->first_fat.entries, 0xDEADBEEF,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    cfs->first_fat.next_fat_table = ROOT_DIR_BLOCK + 1;

    // Filling second FAT
    second_fat->next_fat_table = FAT_BLOCK_END;

    // Writing the structure to a file
    FILE *fp =
        fopen("build/tests/find_first_free_block.on_second_fat.test.cfs", "w");
    if (fwrite(cfs, sizeof(struct CryptFS) + sizeof(struct CryptFS_FAT), 1, fp)
        != 1)
        cr_assert(false, "Failed to write the structure to a file");
    fclose(fp);

    // Reading the structure from the file
    int64_t result = find_first_free_block(&cfs->first_fat);
    cr_assert_eq(result, NB_FAT_ENTRIES_PER_BLOCK, "result = %ld", result);

    free(cfs);
}

Test(find_first_free_block, on_second_fat_not_contigious, .timeout = 10,
     .init = cr_redirect_stdout)
{
    set_device_path(
        "build/tests/"
        "find_first_free_block.on_second_fat_not_contigious.test.cfs");

    format_fs("build/tests/"
              "find_first_free_block.on_second_fat_not_contigious.test.cfs",
              "build/tests/"
              "find_first_free_block.on_second_fat_not_contigious.public.pem",
              "build/tests/"
              "find_first_free_block.on_second_fat_not_contigious.private.pem",
              NULL, NULL);

    struct CryptFS_FAT *first_fat = xaligned_calloc(
        sizeof(struct CryptFS_FAT), 1, sizeof(struct CryptFS_FAT));

    struct CryptFS_FAT *second_fat = xaligned_calloc(
        sizeof(struct CryptFS_FAT), 1, sizeof(struct CryptFS_FAT));

    // Filling first FAT
    memset(first_fat->entries, 0xDEADBEEF,
           NB_FAT_ENTRIES_PER_BLOCK * sizeof(struct CryptFS_FAT_Entry));
    first_fat->next_fat_table = ROOT_DIR_BLOCK + 2;

    // Filling second FAT
    memset(second_fat->entries, 0xDEADBEEF,
           (NB_FAT_ENTRIES_PER_BLOCK - 1) * sizeof(struct CryptFS_FAT_Entry));
    second_fat->next_fat_table = FAT_BLOCK_END;

    // Writing the FATs to the image
    write_blocks(FIRST_FAT_BLOCK, 1, first_fat);
    write_blocks(ROOT_DIR_BLOCK + 2, 1, second_fat);

    // Reading the structure from the file
    int64_t result = find_first_free_block(first_fat);
    cr_assert_eq(result,
                 NB_FAT_ENTRIES_PER_BLOCK + (NB_FAT_ENTRIES_PER_BLOCK - 1),
                 "result = %ld", result);

    free(first_fat);
    free(second_fat);

    // Deleting the file
    if (remove("build/tests/"
               "find_first_free_block.on_second_fat_not_contigious.test.cfs")
        != 0)
        cr_assert(false, "Failed to remove the file");
}

Test(create_fat, second_fat, .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS *cfs = xcalloc(1, sizeof(struct CryptFS));

    // Setting the device and block size for read/write operations
    set_device_path("build/tests/create_fat.second_fat.test.cfs");

    format_fs("build/tests/create_fat.second_fat.test.cfs",
              "build/tests/create_fat.second_fat.public.pem",
              "build/tests/create_fat.second_fat.private.pem", NULL, NULL);

    FILE *fp = fopen("build/tests/create_fat.second_fat.test.cfs", "r");
    if (fread(cfs, sizeof(struct CryptFS), 1, fp) != 1)
        cr_assert(false, "Failed to read the structure from a file");
    fclose(fp);

    // Reading the structure from the file
    int64_t result = create_fat(&cfs->first_fat);
    cr_assert_eq(result, ROOT_DIR_BLOCK + 1, "result = %ld", result);

    // Deleting the file
    if (remove("build/tests/create_fat.second_fat.test.cfs") != 0)
        cr_assert(false, "Failed to remove the file");

    free(cfs);
}

Test(create_fat, third_fat, .init = cr_redirect_stdout, .timeout = 10)
{
    struct CryptFS *cfs = xcalloc(1, sizeof(struct CryptFS));

    // Setting the device and block size for read/write operations
    set_device_path("build/tests/create_fat.third_fat.test.cfs");

    format_fs("build/tests/create_fat.third_fat.test.cfs",
              "build/tests/create_fat.third_fat.public.pem",
              "build/tests/create_fat.third_fat.private.pem", NULL, NULL);

    FILE *fp = fopen("build/tests/create_fat.third_fat.test.cfs", "r");
    if (fread(cfs, sizeof(struct CryptFS), 1, fp) != 1)
        cr_assert(false, "Failed to read the structure from a file");
    fclose(fp);

    // Reading the structure from the file
    int64_t result1 = create_fat(&cfs->first_fat);
    int64_t result2 = create_fat(&cfs->first_fat);
    cr_assert_eq(result1, ROOT_DIR_BLOCK + 1, "result1 = %ld", result1);
    cr_assert_eq(result2, ROOT_DIR_BLOCK + 2, "result2 = %ld", result2);

    // Deleting the file
    if (remove("build/tests/create_fat.third_fat.test.cfs") != 0)
        cr_assert(false, "Failed to remove the file");

    free(cfs);
}
