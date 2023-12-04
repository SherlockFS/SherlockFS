#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>

#include "block.h"
#include "cryptfs.h"
#include "format.h"
#include "print.h"
#include "writefs.h"
#include "xalloc.h"

Test(is_already_formatted, not_formated, .timeout = 10)
{
    cr_assert(!is_already_formatted("tests/format_test.c"));
}

Test(is_already_formatted, formated, .init = cr_redirect_stdout, .timeout = 10)
{
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
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/blocksize.test.shlkfs");

    struct CryptFS *shlkfs = xcalloc(1, sizeof(struct CryptFS));

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
    // Set the device (global variable) to the file (used by read/write_blocks)
    set_device_path("build/tests/integrity.test.shlkfs");

    struct CryptFS *shlkfs_before = xcalloc(1, sizeof(struct CryptFS));
    struct CryptFS *shlkfs_after = xcalloc(1, sizeof(struct CryptFS));

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
    read_blocks(0, 67, shlkfs_after);

    // Check the integrity of the CryptFS
    for (size_t i = 0; i < sizeof(struct CryptFS); i++)
        if (((char *)shlkfs_before)[i] != ((char *)shlkfs_after)[i])
        {
            // Print the first 10 byte that are different
            for (size_t j = 0; j < 10; j++)
                cr_log_error("%02x != %02x\n", ((char *)shlkfs_before)[i + j],
                             ((char *)shlkfs_after)[i + j]);
            cr_assert(0);
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
