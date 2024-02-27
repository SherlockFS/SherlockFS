#ifndef DELUSER_H
#define DELUSER_H

#include "cryptfs.h"

/**
 * @brief Delete a user public key from the keys storage
 *
 * @note No action is performed if the public key is not in the keys storage
 *
 * @param device_path The path of the device to add user to
 * @param my_private_key_path A path to the current user private key
 * @param deleting_user_public_key_path A path to the public key to remove from
 * the keys storage
 * @return int 0 if success, -1 not deleted for any reason
 */
int cryptfs_deluser(const char *device_path, const char *my_private_key_path,
                    const char *deleting_user_public_key_path);
/**
 * @brief Count the number of available key slots in the keys storage
 *
 * @param keys_storage The keys storage
 * @return size_t The number of available key slots
 */
size_t available_key_slots(const struct CryptFS_KeySlot *keys_storage);

/**
 * @brief Count the number of occupied key slots in the keys storage
 *
 * @param keys_storage The keys storage
 * @return size_t The number of occupied key slots
 */
size_t occupied_key_slots(const struct CryptFS_KeySlot *keys_storage);

#endif /* DELUSER_H */
