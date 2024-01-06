#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>
#include <stddef.h>

/**
 * @brief Do a SHA256 hash of the given buffer.
 *
 * @param data The data to hash.
 * @param len_data The length of the data to hash.
 * @return unsigned char* The hash. (of length SHA256_DIGEST_LENGTH)
 */
unsigned char *sha256_data(void *data, size_t len_data);

/**
 * @brief RSA public compoenent (N and E) hashing function for a KeySlot
 *
 * @param rsa_public The RSA key to hash
 * @return unsigned char* The hash. (of length SHA256_DIGEST_LENGTH)
 */
unsigned char *hash_rsa_public_key(EVP_PKEY *rsa_public);

#endif /* HASH_H */
