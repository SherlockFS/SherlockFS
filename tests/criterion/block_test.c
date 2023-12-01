#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <openssl/rand.h>
#include <signal.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "format.h"
#include "xalloc.h"

Test(set_block_size, bad_size, .init = cr_redirect_stderr, .timeout = 10,
     .signal = SIGABRT)
{
    set_block_size(42);
}

Test(set_block_size, good_size, .timeout = 10)
{
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);
}

Test(block, read_write, .init = cr_redirect_stdout, .timeout = 10)
{
    set_device_path("build/block_read_write.test.cfs");
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

    format_fs("build/block_read_write.test.cfs", NULL, NULL);

    uint8_t *buffer_before = xmalloc(1, get_block_size());
    uint8_t *buffer_after = xcalloc(1, get_block_size());

    cr_assert(RAND_bytes(buffer_before, get_block_size()) == 1);

    int ret = write_blocks(0, 1, buffer_before);
    cr_assert_eq(ret, 0);
    ret = read_blocks(0, 1, buffer_after);
    cr_assert_eq(ret, 0);
    cr_assert_arr_eq(buffer_before, buffer_after, get_block_size());

    // Remove the file
    if (remove("build/block_read_write.test.cfs") != 0)
        cr_assert(false, "Impossible to delete the file");

    free(buffer_before);
    free(buffer_after);
}

Test(block, read_write_with_encryption_decryption, .init = cr_redirect_stdout,
     .timeout = 10)
{
    set_device_path("build/block_read_write_with_encryption.test.cfs");
    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);

    format_fs("build/block_read_write_with_encryption.test.cfs", NULL, NULL);

    unsigned char *aes_key = generate_aes_key();

    unsigned char *buffer_before_encryption = xcalloc(1, get_block_size());
    unsigned char *buffer_after_decryption = xcalloc(1, get_block_size());

    cr_assert_eq(RAND_bytes(buffer_before_encryption, get_block_size()), 1);

    int ret =
        write_blocks_with_encryption(aes_key, 0, 1, buffer_before_encryption);
    cr_assert_eq(ret, 0);
    ret = read_blocks_with_decryption(aes_key, 0, 1, buffer_after_decryption);
    cr_assert_eq(ret, 0);
    cr_assert_arr_eq(buffer_before_encryption, buffer_after_decryption,
                     get_block_size());
    free(aes_key);
    free(buffer_before_encryption);
    free(buffer_after_decryption);
}
