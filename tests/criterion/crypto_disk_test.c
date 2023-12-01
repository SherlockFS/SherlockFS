#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "crypto.h"
#include "xalloc.h"

Test(crypto_disk, load_rsa_keypair_from_disk, .init = cr_redirect_stdout,
     .timeout = 10)
{
    remove("build/crypto_disk__load_rsa_keypair_from_disk");
    int dir_res = mkdir("build/crypto_disk__load_rsa_keypair_from_disk", 0755);
    if (dir_res != 0 && errno != EEXIST)
        cr_assert(false, "Impossible to create the directory");

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    write_rsa_keys_on_disk(
        rsa_keypair, "build/crypto_disk__load_rsa_keypair_from_disk/public.pem",
        "build/crypto_disk__load_rsa_keypair_from_disk/private.pem", NULL);
    EVP_PKEY *rsa_keypair_loaded = load_rsa_keypair_from_disk(
        "build/crypto_disk__load_rsa_keypair_from_disk/public.pem",
        "build/crypto_disk__load_rsa_keypair_from_disk/private.pem", NULL);
    cr_assert_eq(EVP_PKEY_eq(rsa_keypair, rsa_keypair_loaded), 1);
    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(rsa_keypair_loaded);
}
