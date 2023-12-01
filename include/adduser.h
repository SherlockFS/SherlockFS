#ifndef ADDUSER_H
#define ADDUSER_H

/**
 * @brief Add a user public key to the cryptfs keys storage
 *
 * @param device_path The path to the device
 * @param other_public_key_path A path to a public key to add
 * @param my_private_key_path A path to a private key already registered
 */
void cryptfs_adduser(char *device_path, char *other_public_key_path,
                     char *my_private_key_path);

#endif /* ADDUSER_H */
