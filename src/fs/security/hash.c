#include "hash.h"

#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "cryptfs.h"
#include "print.h"
#include "xalloc.h"

unsigned char *sha256_data(const void *data, size_t len_data)
{
    unsigned char *hash = xmalloc(SHA256_DIGEST_LENGTH, 1);

    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();
    if (!sha256_ctx)
        internal_error_exit("Failed to allocate SHA256 context\n",
                            EXIT_FAILURE);

    if (EVP_DigestInit(sha256_ctx, EVP_sha256()) != 1
        || EVP_DigestUpdate(sha256_ctx, data, len_data) != 1
        || EVP_DigestFinal(sha256_ctx, hash, NULL) != 1)
        internal_error_exit("Failed to compute SHA256 hash\n", errno);

    EVP_MD_CTX_free(sha256_ctx);
    return hash;
}
