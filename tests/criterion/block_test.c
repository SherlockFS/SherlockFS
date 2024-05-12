#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>
#include <signal.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "format.h"
#include "xalloc.h"

Test(block, read_write, .init = cr_redirect_stdout, .timeout = 10)
{
    system("dd if=/dev/zero of=build/tests/block_read_write.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    set_device_path("build/tests/block_read_write.test.shlkfs");

    format_fs("build/tests/block_read_write.test.shlkfs",
              "build/tests/block_read_write.test.public.pem",
              "build/tests/block_read_write.test.private.pem", "label", NULL,
              NULL);

    uint8_t *buffer_before = xcalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    uint8_t *buffer_after = xcalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);

    cr_assert(RAND_bytes(buffer_before, CRYPTFS_BLOCK_SIZE_BYTES) == 1);

    int ret = write_blocks(0, 1, buffer_before);
    cr_assert_eq(ret, 0);
    ret = read_blocks(0, 1, buffer_after);
    cr_assert_eq(ret, 0);
    cr_assert_arr_eq(buffer_before, buffer_after, CRYPTFS_BLOCK_SIZE_BYTES);

    // Remove the file
    if (remove("build/tests/block_read_write.test.shlkfs") != 0)
        cr_assert(false, "Impossible to delete the file");

    free(buffer_before);
    free(buffer_after);
}

Test(block, read_write_with_encryption_decryption, .init = cr_redirect_stdout,
     .timeout = 10)
{
    system("dd if=/dev/zero "
           "of=build/tests/block_read_write_with_encryption.test.shlkfs "
           "bs=4096 count=1000 2> /dev/null");

    set_device_path("build/tests/block_read_write_with_encryption.test.shlkfs");

    format_fs("build/tests/block_read_write_with_encryption.test.shlkfs",
              "build/tests/block_read_write_with_encryption.test.public.pem",
              "build/tests/block_read_write_with_encryption.test.private.pem",
              "label", NULL, NULL);

    unsigned char *aes_key = generate_aes_key();

    unsigned char *buffer_before_encryption =
        xcalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);
    unsigned char *buffer_after_decryption =
        xcalloc(1, CRYPTFS_BLOCK_SIZE_BYTES);

    cr_assert_eq(RAND_bytes(buffer_before_encryption, CRYPTFS_BLOCK_SIZE_BYTES),
                 1);

    int ret =
        write_blocks_with_encryption(aes_key, 0, 1, buffer_before_encryption);
    cr_assert_eq(ret, 0);
    ret = read_blocks_with_decryption(aes_key, 0, 1, buffer_after_decryption);
    cr_assert_eq(ret, 0);
    cr_assert_arr_eq(buffer_before_encryption, buffer_after_decryption,
                     CRYPTFS_BLOCK_SIZE_BYTES);
    free(aes_key);
    free(buffer_before_encryption);
    free(buffer_after_decryption);
}
