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
#include "fat.h"
#include "format.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

int main(void)
{
    // Setting the device and block size for read/write operations
    set_device_path("tests/create_fat.second_fat.test.shlkfs");

    format_fs("tests/create_fat.second_fat.test.shlkfs",
              "tests/create_fat.second_fat.public.pem",
              "tests/create_fat.second_fat.private.pem", NULL, NULL);

    // Reading the structure from the file
    unsigned char *ase_key =
        extract_aes_key("tests/create_fat.second_fat.test.shlkfs",
                        "tests/create_fat.second_fat.private.pem");

    int second_fat_index = create_fat(ase_key);
    assert(second_fat_index == ROOT_DIR_BLOCK + 2);

    struct CryptFS_FAT fat_full_1 = { 0 };
    memset(&fat_full_1, BLOCK_END, sizeof(fat_full_1));
    fat_full_1.next_fat_table = second_fat_index;

    struct CryptFS_FAT fat_full_2 = { 0 };
    memset(&fat_full_2, BLOCK_END, sizeof(fat_full_2));
    fat_full_2.next_fat_table = BLOCK_END;

    write_blocks_with_encryption(ase_key, FIRST_FAT_BLOCK, 1, &fat_full_1);
    write_blocks_with_encryption(ase_key, ROOT_DIR_BLOCK + 2, 1, &fat_full_2);

    int64_t result = find_first_free_block(ase_key);
    assert(result == (long int)(-2 * NB_FAT_ENTRIES_PER_BLOCK));

    result = create_fat(ase_key);

    assert(result == 2 * NB_FAT_ENTRIES_PER_BLOCK);
    // Deleting the file
    if (remove("tests/create_fat.second_fat.test.shlkfs") != 0)
        return -1;

    free(ase_key);
    return 0;
}

#pragma GCC diagnostic pop
