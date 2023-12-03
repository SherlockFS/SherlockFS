#ifndef WRITEFS_H
#define WRITEFS_H

#include "cryptfs.h"

/**
 * @brief Write the CryptFS headers to the device
 *
 * @param device_path Path to the CryptFS device
 * @param cryptfs Pointer to a CryptFS struct to store the headers
 */
void write_cryptfs_headers(char *device_path, struct CryptFS *cryptfs);

#endif /* WRITEFS_H */
