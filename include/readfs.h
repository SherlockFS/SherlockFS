#ifndef READFS_H
#define READFS_H

#include "cryptfs.h"

/**
 * @brief Read the headers of a CryptFS device
 *
 * @param device_path Path to the CryptFS device
 * @return struct CryptFS* Pointer to a CryptFS struct
 */
struct CryptFS *read_cryptfs_headers(const char *device_path);

#endif /* READFS_H */
