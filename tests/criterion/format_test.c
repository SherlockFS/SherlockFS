#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "format.h"
#include "print.h"
#include "writefs.h"
#include "xalloc.h"

void cr_redirect_stdall(void);

Test(is_already_formatted, not_existing, .timeout = 10)
{
    cr_assert(!is_already_formatted("tests/not_existing.blank"));
}

Test(is_already_formatted, not_formated, .timeout = 10)
{
    cr_assert(!is_already_formatted("tests/criterion/format_test.c"));
}

Test(is_already_formatted, formated, .init = cr_redirect_stdout, .timeout = 10)
{
    system("dd if=/dev/zero of=build/tests/format.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/format.test.shlkfs");

    format_fs("build/tests/format.test.shlkfs",
              "build/tests/format.test.pub.pem",
              "build/tests/format.test.private.pem", NULL, NULL);
    cr_assert(is_already_formatted("build/tests/format.test.shlkfs"));

    // Detele the file
    if (remove("build/tests/format.test.shlkfs") != 0)
    {
        perror("Impossible to delete the file");
        exit(EXIT_FAILURE);
    }
}

Test(is_already_formatted, not_CRYPTFS_BLOCK_SIZE_BYTES_blocksize,
     .init = cr_redirect_stdout, .timeout = 10)
{
    system("dd if=/dev/zero of=build/tests/blocksize.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/blocksize.test.shlkfs");

    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));

    format_fs("build/tests/blocksize.test.shlkfs",
              "build/tests/blocksize.test.pub.pem",
              "build/tests/blocksize.test.private.pem", NULL, NULL);

    // Change the blocksize
    shlkfs->header.blocksize = 1024;

    // Write the CryptFS to the file
    write_cryptfs_headers("build/tests/blocksize.test.shlkfs", shlkfs);

    cr_assert(!is_already_formatted("build/tests/blocksize.test.shlkfs"));

    free(shlkfs);
}

Test(format_fs, integrity, .init = cr_redirect_stdout, .timeout = 10)
{
    system("dd if=/dev/zero of=build/tests/integrity.test.shlkfs bs=4096 "
           "count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/integrity.test.shlkfs");

    struct CryptFS *shlkfs_before =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));
    struct CryptFS *shlkfs_after =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));

    format_fill_filesystem_struct(shlkfs_before, NULL, NULL,
                                  "build/tests/integrity.test.pub.pem",
                                  "build/tests/integrity.test.private.pem");

    // Write the CryptFS to the file
    FILE *file = fopen("build/tests/integrity.test.shlkfs", "w");
    if (file == NULL
        || fwrite(shlkfs_before, sizeof(*shlkfs_before), 1, file) != 1)
        error_exit("Impossible to write the filesystem structure on the disk\n",
                   EXIT_FAILURE);
    fclose(file);

    // Read the the CryptFS
    read_blocks(0, ROOT_DIR_BLOCK + 1, shlkfs_after);

    // Check the integrity of the CryptFS
    for (size_t i = 0; i < sizeof(struct CryptFS); i++)
        if (((char *)shlkfs_before)[i] != ((char *)shlkfs_after)[i])
        {
            cr_log_error("Integrity error at byte '%zu'\n", i);
            // Print the first 10 byte that are different
            for (size_t j = 0; j < 10; j++)
                cr_log_error("%02d != %02d\n", ((char *)shlkfs_before)[i + j],
                             ((char *)shlkfs_after)[i + j]);
            cr_assert(false);
        }

    free(shlkfs_before);
    free(shlkfs_after);

    // Delete the file
    if (remove("build/tests/integrity.test.shlkfs") != 0)
    {
        perror("Impossible to delete the file");
        exit(EXIT_FAILURE);
    }
}

Test(is_already_formatted, formated_check_content, .init = cr_redirect_stdout,
     .timeout = 10)
{
    system("dd if=/dev/zero of=build/tests/formated_check_content.test.shlkfs "
           "bs=4096 "
           "count=1000 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/formated_check_content.test.shlkfs");

    format_fs("build/tests/formated_check_content.test.shlkfs",
              "build/tests/formated_check_content.test.pub.pem",
              "build/tests/formated_check_content.test.private.pem", NULL,
              NULL);
    cr_assert(
        is_already_formatted("build/tests/formated_check_content.test.shlkfs"));

    // Read block HEADER_BLOCK_INDEX
    struct CryptFS_Header *header =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    cr_assert(read_blocks(HEADER_BLOCK, 1, header) == 0);

    // Check the content of the block
    cr_assert_eq(header->blocksize, CRYPTFS_BLOCK_SIZE_BYTES);
    cr_assert_eq(header->magic, CRYPTFS_MAGIC);
    cr_assert_eq(header->last_fat_block, FIRST_FAT_BLOCK);
    cr_assert_eq(header->version, CRYPTFS_VERSION);

    struct CryptFS_KeySlot *keyslots =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, NB_ENCRYPTION_KEYS,
                        sizeof(struct CryptFS_KeySlot));
    uint8_t *zeros = xcalloc(CRYPTFS_BLOCK_SIZE_BYTES, 1);

    // Read block KEYS_STORAGE_BLOCK
    cr_assert(read_blocks(KEYS_STORAGE_BLOCK, NB_ENCRYPTION_KEYS, keyslots)
              == 0);

    // Check the content of the block
    cr_assert_eq(keyslots[0].occupied, 1);
    cr_assert_neq(keyslots[0].rsa_e, 0);
    cr_assert_arr_neq(keyslots[0].rsa_n, zeros, RSA_KEY_SIZE_BYTES);
    cr_assert_arr_neq(keyslots[0].aes_key_ciphered, zeros, RSA_KEY_SIZE_BYTES);

    for (size_t i = 1; i < NB_ENCRYPTION_KEYS; i++)
        cr_assert_eq(keyslots[i].occupied, 0);

    unsigned char *aes_key = extract_aes_key(
        "build/tests/formated_check_content.test.shlkfs",
        "build/tests/formated_check_content.test.private.pem", NULL);

    cr_assert_neq(aes_key, NULL);

    // Read block FIRST_FAT_BLOCK
    struct CryptFS_FAT *fat =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // Check if content is encrypted
    cr_assert(read_blocks(FIRST_FAT_BLOCK, 1, fat) == 0);
    cr_assert_arr_neq(fat, zeros, CRYPTFS_BLOCK_SIZE_BYTES);

    // Check the content of the block
    cr_assert(read_blocks_with_decryption(aes_key, FIRST_FAT_BLOCK, 1, fat)
              == 0);
    cr_assert_eq(fat->next_fat_table, BLOCK_END);
    for (size_t i = 0; i <= ROOT_DIR_BLOCK; i++)
        cr_assert_eq(fat->entries[i].next_block, BLOCK_END);

    // Read block ROOT_ENTRY_BLOCK
    struct CryptFS_Entry *root_entry =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);

    // Check if content is encrypted
    cr_assert(read_blocks(ROOT_ENTRY_BLOCK, 1, root_entry) == 0);
    cr_assert_arr_neq(root_entry, zeros, CRYPTFS_BLOCK_SIZE_BYTES);

    // Check the content of the block
    cr_assert(read_blocks_with_decryption(aes_key, ROOT_ENTRY_BLOCK, 1, root_entry)
              == 0);
    cr_assert_eq(root_entry->used, 1);
    cr_assert_eq(root_entry->type, ENTRY_TYPE_DIRECTORY);
    cr_assert_eq(root_entry->size, 0);
    cr_assert_eq(root_entry->nlink, 1);
    cr_assert_str_empty(root_entry->name);

    // Read block ROOT_DIR_BLOCK
    struct CryptFS_Directory *root_dir =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, CRYPTFS_BLOCK_SIZE_BYTES);
    
    // Check if content is encrypted
    cr_assert(read_blocks(ROOT_DIR_BLOCK, 1, root_dir) == 0);
    cr_assert_arr_neq(root_dir, zeros, CRYPTFS_BLOCK_SIZE_BYTES);

    // Check the content of the block
    cr_assert(read_blocks_with_decryption(aes_key, ROOT_DIR_BLOCK, 1, root_dir)
              == 0);
    cr_assert_eq(root_dir->current_directory_entry.directory_block, ROOT_ENTRY_BLOCK);
    cr_assert_eq(root_dir->current_directory_entry.directory_index, 0);

    // Free
    free(header);
    free(keyslots);
    free(aes_key);
    free(zeros);
    free(fat);
    free(root_entry);
    free(root_dir);

    // Delete the file
    if (remove("build/tests/formated_check_content.test.shlkfs") != 0)
    {
        perror("Impossible to delete the file");
        exit(EXIT_FAILURE);
    }
}

Test(format, too_small, .init = cr_redirect_stdall, .timeout = 10,
     .exit_code = 1)
{
    system("dd if=/dev/zero of=build/tests/too_small.test.shlkfs bs=4096 "
           "count=42 2> /dev/null");

    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/too_small.test.shlkfs");

    format_fs("build/tests/too_small.test.shlkfs",
              "build/tests/too_small.test.pub.pem",
              "build/tests/too_small.test.private.pem", NULL, NULL);
}
