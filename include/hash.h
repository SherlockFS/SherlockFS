#ifndef HASH_H
#define HASH_H

#include <stddef.h>

/**
 * @brief Do a SHA256 hash of the given buffer.
 *
 * @param data The data to hash.
 * @param len_data The length of the data to hash.
 * @return unsigned char* The hash. (of length SHA256_DIGEST_LENGTH)
 */
unsigned char *sha256_data(void *data, size_t len_data);

#endif /* HASH_H */
