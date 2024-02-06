#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "cryptfs.h"

/**
 * @brief Encrypts `data` of size `data_size` with `rsa_key` public key.
 *
 * @param rsa_key The RSA (public) key to use for encryption.
 * @param data The data to encrypt.
 * @param data_size The size of the data to encrypt.
 * @param encrypted_data_size The size of the encrypted data (returned).
 * @return unsigned char* The encrypted data.
 */
unsigned char *rsa_encrypt_data(EVP_PKEY *rsa_key, const void *data,
                                size_t data_size, size_t *encrypted_data_size);

/**
 * @brief Decrypts `encrypted_data` of size `encrypted_data_size` with
 * `rsa_key` private key.
 *
 * @param rsa_key The RSA (private) key to use for decryption.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_size The size of the data to decrypt.
 * @param decrypted_data_size The size of the decrypted data (returned).
 * @return unsigned char* The decrypted data.
 */
unsigned char *rsa_decrypt_data(EVP_PKEY *rsa_key, const void *encrypted_data,
                                size_t encrypted_data_size,
                                size_t *decrypted_data_size);

/**
 * @brief Encrypts `data` of size `data_size` with `aes_key` key.
 *
 * @param aes_key The AES key to use for encryption.
 * @param data The data to encrypt.
 * @param data_size The size of the data to encrypt.
 * @param encrypted_data_size The size of the encrypted data (returned).
 * @return unsigned char* The encrypted data.
 */
unsigned char *aes_encrypt_data(const unsigned char *aes_key, const void *data,
                                size_t data_size, size_t *encrypted_data_size);

/**
 * @brief Decrypts `encrypted_data` of size `encrypted_data_size` with
 * `aes_key` key.
 *
 * @param aes_key The AES key to use for decryption.
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_size The size of the data to decrypt.
 * @param decrypted_data_size The size of the decrypted data (returned).
 * @return unsigned char* The decrypted data.
 */
unsigned char *aes_decrypt_data(const unsigned char *aes_key,
                                const void *encrypted_data,
                                size_t encrypted_data_size,
                                size_t *decrypted_data_size);

/**
 * @brief Generates a random AES key.
 *
 * @return unsigned char* The generated AES key.
 */
unsigned char *generate_aes_key(void);

/**
 * @brief Generates a random RSA keypair.
 *
 * @return EVP_PKEY* The generated RSA keypair.
 */
EVP_PKEY *generate_rsa_keypair(void);

/**
 * @brief Checks if the given RSA key is valid.
 *
 * @note The key is considered valid if:
 * - It is not NULL,
 * - It is a RSA key,
 * - The RSA key is valid (RSA_check_key),
 * - The RSA modulus is RSA_KEY_SIZE_BYTES bits long,
 * - The RSA exponent is a uint32_t.
 *
 * @param rsa_key The RSA key to check.
 * @return true
 * @return false
 */
bool is_key_valid(EVP_PKEY *rsa_key);

/**
 * @brief Stores the RSA modulus and the RSA public exponent in a keys storage.
 *
 * @param keys_storage The keys storage.
 * @param rsa_keypair The RSA keypair: modulus and public exponent will be
 * stored.
 * @param aes_key The AES key: RSAPUB_Encrypt(aes_key) will be stored.
 */
void store_keys_in_keys_storage(struct CryptFS_KeySlot *keys_storage,
                                EVP_PKEY *rsa_keypair,
                                const unsigned char *aes_key);

/**
 * @brief Writes the RSA private and public keys to a file.
 *
 * @param rsa_keypair The RSA keypair which is written.
 * @param public_key_path The path where the public key will be written.
 * @param private_key_path The path where the private key will be written.
 * @param passphrase The passphrase used to encrypt the keys.
 * NULL if the keys are not encrypted.
 */
void write_rsa_keys_on_disk(EVP_PKEY *rsa_keypair, const char *public_key_path,
                            const char *private_key_path, char *passphrase);

/**
 * @brief Find the key in the keys storage which matches the given RSA
 * keypair (user one).
 *
 * @param rsa_private The RSA of the user.
 * @param keys_storage The keys storage to search in.
 * @return ssize_t The index of the key in the header, -1 if not found.
 */
ssize_t find_rsa_matching_key(EVP_PKEY *rsa_private,
                              const struct CryptFS_KeySlot *keys_storage);

/**
 * @brief Loads the RSA private and public keys from the given file.
 *
 * @param public_key_path The path of the public key file.
 * @param private_key_path The path of the private key file.
 * @param passphrase The passphrase used to decrypt the keys,
 * NULL if the keys are not encrypted.
 * @return EVP_PKEY* The loaded RSA keypair.
 */
EVP_PKEY *load_rsa_keypair_from_disk(const char *public_key_path,
                                     const char *private_key_path,
                                     char *passphrase);

/**
 * @brief Get the RSA keys home paths (public and private).
 *
 * @param public_key_path Returned public key path.
 * @param private_key_path Returned private key path.
 */
void get_rsa_keys_home_paths(char **public_key_path, char **private_key_path);

/**
 * @brief Loads the RSA private and public keys from the current user's home
 * directory.
 *
 * @param passphrase Gets filled with the passphrase the user enters if he
 * decides to.
 * @return EVP_PKEY* The loaded RSA keypair.
 */
EVP_PKEY *load_rsa_keypair_from_home(char **passphrase);

/**
 * @brief Extracts the AES key from the keys storage.
 *
 * @param device_path A path of the device to extract the AES key from
 * @param private_key_path A path of the private key file.
 * @return unsigned char* The extracted AES key., or NULL if the key cannot be
 * extracted.
 */
unsigned char *extract_aes_key(const char *device_path,
                               const char *private_key_path);

#endif /* CRYPTO_H */
