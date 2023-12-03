#ifndef ADDUSER_H
#define ADDUSER_H

/**
 * @brief Add a user public key to the cryptfs keys storage
 *
 * @param device_path The path of the device to add user to
 * @param other_public_key_path A path to of the public key to add
 * @param my_private_key_path A path of the private key already registered
 * @return int 0 if success, -1 user already exists (not added)
 */
int cryptfs_adduser(char *device_path, char *other_public_key_path,
                    char *my_private_key_path);

#endif /* ADDUSER_H */
