#include <assert.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "adduser.h"
#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "deluser.h"
#include "entries.h"
#include "fat.h"
#include "format.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

int parcours_fat_print(const unsigned char *aes_key, block_t directory_block,
                       uint32_t directory_index)
{
    printf("START:");
    // allocate struct for reading directory_block
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    if (read_blocks_with_decryption(aes_key, directory_block, 1, dir) == -1)
        return BLOCK_ERROR;

    // Get the correct Entry
    struct CryptFS_Entry entry = dir->entries[directory_index];

    uint64_t block = entry.start_block;
    // printf("START_BLOCK=%lu\n", block);
    int count = 1;
    printf("count=%u FAT[%lu]=%u\n", count, block,
           read_fat_offset(aes_key, block));
    while ((int)read_fat_offset(aes_key, block) != BLOCK_END)
    {
        count++;
        block = read_fat_offset(aes_key, block);
        printf("count=%u FAT[%lu]=%u\n", count, block,
               read_fat_offset(aes_key, block));
    }
    return 0;
}

int main(void)
{
    // Setting the device and block size for read/write operations
    set_device_path("tests/entry_write_buffer_from.test.shlkfs");

    format_fs("tests/entry_write_buffer_from.test.shlkfs",
              "tests/entry_write_buffer_from.public.pem",
              "tests/entry_write_buffer_from.private.pem", NULL, NULL);

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
    unsigned char *ase_key =
        extract_aes_key("tests/entry_write_buffer_from.test.shlkfs",
                        "tests/entry_write_buffer_from.private.pem");

    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1,
                                 &shlkfs->first_fat);
    write_blocks_with_encryption(ase_key, ROOT_ENTRY_BLOCK + 2, 1, second_fat);

    // Create a directory
    int64_t dir_block = find_first_free_block_safe(ase_key);
    struct CryptFS_Directory *dir = xaligned_alloc(
        CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS_Directory));

    // Update FAT
    write_fat_offset(ase_key, dir_block, BLOCK_END);

    // Create an entry
    struct CryptFS_Entry new_dir = { .used = 1,
                                     .type = ENTRY_TYPE_DIRECTORY,
                                     .start_block = 0,
                                     .name = "TEST",
                                     .size = 0,
                                     .uid = 1000,
                                     .gid = 1000,
                                     .mode = 777,
                                     .atime = 1,
                                     .mtime = 0,
                                     .ctime = 0 };
    dir->entries[0] = new_dir;
    write_blocks_with_encryption(ase_key, dir_block, 1, dir);

    // adding symlink
    char *path = "/usr/bin/你好shlkfs";
    char *name = "Symlink_test";
    uint32_t res = entry_create_symlink(ase_key, dir_block, 0, name, path);
    printf("res=%d\n", res);

    // Update dir_block
    read_blocks_with_decryption(ase_key, dir_block, 1, dir);

    // Check TEST directory metadata
    read_blocks_with_decryption(ase_key, dir_block, 1, dir);
    struct CryptFS_Entry TEST_entry = dir->entries[0];
    assert(TEST_entry.size == 1);

    // Check Symlink
    read_blocks_with_decryption(ase_key, TEST_entry.start_block, 1, dir);
    struct CryptFS_Entry Symlink_entry = dir->entries[0];
    assert(Symlink_entry.type == ENTRY_TYPE_SYMLINK);
    assert(strcmp(Symlink_entry.name, name) == 0);
    assert(Symlink_entry.start_block != 0);
    assert(Symlink_entry.size == strlen(path));
    // buff
    char *buff1 = malloc(strlen(path));
    entry_read_raw_data(ase_key, TEST_entry.start_block, 0, 0, buff1,
                        strlen(path));
    assert(res == 0);

    printf("File name=%s\n", dir->entries[0].name);
    printf(buff1);
    printf("\n");
    printf("File used=%u\n", dir->entries[0].used);
    printf("File size=%lu\n", dir->entries[0].size);
    printf("File start_block=%lu\n", dir->entries[0].start_block);

    // Reading entries in Parent Directory
    // read_blocks_with_decryption(ase_key, dir->entries[0].start_block, 1,
    // dir);

    // parcours_fat_print(ase_key, Dossier_sec, 0);

    // free(buff);
    free(dir);
    free(ase_key);
    free(shlkfs);

    return 0;
}
