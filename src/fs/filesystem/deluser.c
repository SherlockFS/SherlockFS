#include "deluser.h"

#include <assert.h>

#include "crypto.h"
#include "format.h"
#include "io.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "string.h"
#include "writefs.h"

int cryptfs_deluser(char *device_path, char *my_private_key_path,
                    char *deleting_user_public_key_path)
{
    // Check if the device is already formatted
    if (!is_already_formatted(device_path))
    {
        error_exit(
            "The device '%s' is not formatted. Please format it first.\n",
            EXIT_FAILURE, device_path);
    }

    // Loading the my private key from disk in memory
    print_info("Loading my private key from disk...\n");
    EVP_PKEY *my_private_rsa =
        load_rsa_keypair_from_disk(NULL, my_private_key_path, NULL);

    // Loading the other user public key from disk in memory
    print_info("Loading user to delete public key from disk...\n");
    EVP_PKEY *deluser_rsa =
        load_rsa_keypair_from_disk(deleting_user_public_key_path, NULL, NULL);

    // Find matching RSA key in the keys storage
    print_info("Reading the headers of the device '%s'...\n", device_path);
    struct CryptFS *cryptfs = read_cryptfs_headers(device_path);

    // Check if my key is in the keys storage
    ssize_t index_my_user =
        find_rsa_matching_key(my_private_rsa, cryptfs->keys_storage);
    if (index_my_user == -1)
    {
        print_warning("The current user public key (corresponding to '%s' "
                      "private key) is not in the keys "
                      "storage of the device '%s'\n",
                      my_private_key_path, device_path);
        free(cryptfs);
        EVP_PKEY_free(my_private_rsa);
        EVP_PKEY_free(deluser_rsa);
        return -1;
    }

    // Check if the key to delete is in the keys storage
    ssize_t index_deluser =
        find_rsa_matching_key(deluser_rsa, cryptfs->keys_storage);
    if (index_deluser == -1)
    {
        print_warning("The user with the public key '%s' is not in the keys "
                      "storage of the device '%s'\n",
                      deleting_user_public_key_path, device_path);
        free(cryptfs);
        EVP_PKEY_free(my_private_rsa);
        EVP_PKEY_free(deluser_rsa);
        return -1;
    }

    // Check if there is only one key in the keys storage
    if (occupied_key_slots(cryptfs->keys_storage) == 1)
    {
        print_warning(
            "The user with the public key '%s' (you) is the only user "
            "in the keys storage of the device '%s'. The deletion will not be "
            "performed, aborting.\n",
            deleting_user_public_key_path, device_path);
        free(cryptfs);
        EVP_PKEY_free(my_private_rsa);
        EVP_PKEY_free(deluser_rsa);
        return -1;
    }

    // Check if my key is the key to delete
    if (occupied_key_slots(cryptfs->keys_storage) != 1
        && index_my_user == index_deluser)
    {
        print_warning("You are about to delete your public from the keys "
                      "storage. You will not be able to access the filesystem "
                      "using this key after the deletion.\n");
        print_warning("Are you sure you want to continue? (y/N) ");
        char answer = get_char_from_stdin();

        if (answer != 'y' && answer != 'Y')
        {
            print_info("Aborting...");
            free(cryptfs);
            EVP_PKEY_free(my_private_rsa);
            EVP_PKEY_free(deluser_rsa);
            return -1;
        }
    }

    print_info("Deleting user with key '%s' from the device '%s'...\n",
               deleting_user_public_key_path, device_path);

    // Delete the key from the keys storage
    cryptfs->keys_storage[index_deluser].occupied = 0;
    // memset(&cryptfs->keys_storage[index_deluser], 0,
    // CRYPTFS_BLOCK_SIZE_BYTES);

    // Write the new CryptFS headers on device
    print_info("Writing the new headers on device...\n");
    write_cryptfs_headers(device_path, cryptfs);

    EVP_PKEY_free(my_private_rsa);
    EVP_PKEY_free(deluser_rsa);
    free(cryptfs);

    print_success("The user with the public key '%s' has been deleted from the "
                  "keys storage of the device '%s' successfully!\n",
                  deleting_user_public_key_path, device_path);
    return 0;
}
