#ifndef FORMAT_H
#define FORMAT_H

#include <openssl/evp.h>
#include <stdbool.h>

#include "cryptfs.h"

/**
 * @brief Check if the given file is a valid CryptFS file system.
 *
 * @param device_path Path of the file to check.
 * @return true if the device is a valid CryptFS file system.
 * @return false if the device is not a valid CryptFS file system.
 */
bool is_already_formatted(const char *device_path);

/**
 * @brief File the `struct CryptFS` structure when first formatting the
 * filesystem.
 *
 * @param shlkfs The `struct CryptFS` structure to fill.
 * @param rsa_passphrase The passphrase used to encrypt the RSA private key on
 * disk. Set to NULL if no passphrase is needed.
 * @param existing_rsa_keypair The RSA keypair to use.
 * @param public_key_path The path where the public key will be stored.
 * @param private_key_path The path where the private key will be stored.
 */
void format_fill_filesystem_struct(struct CryptFS *shlkfs, char *rsa_passphrase,
                                   const EVP_PKEY *existing_rsa_keypair,
                                   const char *public_key_path,
                                   const char *private_key_path);

/**
 * @brief Format the given device to a cryptfs file system.
 *
 * @param path The path of the device to format.
 * @param public_key_path The path where the public key will be stored.
 * @param private_key_path The path where the private key will be stored.
 * @param rsa_passphrase The passphrase used to encrypt the RSA private key.
 * Set to NULL if no passphrase is needed.
 * @param existing_rsa_keypair The existing RSA keypair to use.
 */
void format_fs(const char *path, char *public_key_path, char *private_key_path,
               char *rsa_passphrase, EVP_PKEY *existing_rsa_keypair);

/**
 * @brief Check if the keys (public and private) are already generated.
 *
 * @return False if the file does not exist.
 * @return True if the file exist.
 */
bool keypair_in_home_exist(void);
#endif /* FORMAT_H */
