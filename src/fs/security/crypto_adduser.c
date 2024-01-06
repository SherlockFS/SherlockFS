
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "cryptfs.h"
#include "crypto.h"
#include "hash.h"
#include "print.h"
#include "string.h"
#include "xalloc.h"

ssize_t find_rsa_matching_key(EVP_PKEY *rsa_keypair,
                              struct CryptFS_KeySlot *keys_storage)
{
    unsigned char *cmp_hash = hash_rsa_public_key(rsa_keypair);

    uint8_t i = 0;
    for (; i < NB_ENCRYPTION_KEYS; i++)
        if (memcmp(keys_storage[i].rsa_public_hash, cmp_hash,
                   SHA256_DIGEST_LENGTH)
            == 0)
            break;

    free(cmp_hash);
    return i == NB_ENCRYPTION_KEYS ? -1 : i;
}
