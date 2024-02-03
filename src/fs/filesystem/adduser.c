#include "adduser.h"

#include <assert.h>

#include "crypto.h"
#include "format.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"

int cryptfs_adduser(char *device_path, char *other_public_key_path,
                    char *my_private_key_path)
{
    char *passphrase = NULL;

    // Check if the device is already formatted
    if (!is_already_formatted(device_path))
    {
        error_exit(
            "The device '%s' is not formatted. Please format it first.\n",
            EXIT_FAILURE, device_path);
    }

    // Check if my private key is encrypted
    if (rsa_private_is_encrypted(my_private_key_path))
        passphrase = ask_user_passphrase(false);

    // Loading the my private key from disk in memory
    print_info("Loading registred user private key from disk...\n");
    EVP_PKEY *my_rsa =
        load_rsa_keypair_from_disk(NULL, my_private_key_path, passphrase);

    // Loading the other user public key from disk in memory
    print_info("Loading other user public key from disk...\n");
    EVP_PKEY *other_rsa =
        load_rsa_keypair_from_disk(other_public_key_path, NULL, NULL);

    // Find matching RSA key in the keys storage
    struct CryptFS *cryptfs = read_cryptfs_headers(device_path);

    // Check if other user is already in the keys storage
    ssize_t index = find_rsa_matching_key(other_rsa, cryptfs->keys_storage);

    if (index != -1)
    {
        print_warning(
            "The user with the public key '%s' is already in the keys "
            "storage of the device '%s'\n",
            other_public_key_path, device_path);
        free(cryptfs);
        free(passphrase);
        EVP_PKEY_free(my_rsa);
        EVP_PKEY_free(other_rsa);
        return -1;
    }

    print_info("Finding registred user private key in the keys storage...\n");
    index = find_rsa_matching_key(my_rsa, cryptfs->keys_storage);

    if (index == -1)
        error_exit("User private key is not registered in the keys "
                   "storage\n",
                   EXIT_FAILURE);

    // Decrypt the master key
    print_info("Decrypting the master key...\n");
    size_t decrypted_master_key_size = 0;
    unsigned char *decrypted_master_key =
        rsa_decrypt_data(my_rsa, cryptfs->keys_storage[index].aes_key_ciphered,
                         RSA_KEY_SIZE_BYTES, &decrypted_master_key_size);

    assert(decrypted_master_key_size == AES_KEY_SIZE_BYTES);

    print_info("Storing the other user public key in the keys storage and "
               "encrypting the master key with it...\n");
    store_keys_in_keys_storage(cryptfs->keys_storage, other_rsa,
                               decrypted_master_key);

    // Write the new CryptFS headers on device
    print_info("Writing the new headers on device...\n");
    write_cryptfs_headers(device_path, cryptfs);

    // Free memory
    if (passphrase != NULL)
        free(passphrase);
    EVP_PKEY_free(my_rsa);
    EVP_PKEY_free(other_rsa);
    free(decrypted_master_key);
    free(cryptfs);

    print_success("The user with the public key '%s' has been added to the "
                  "keys storage of the device '%s' successfully!\n",
                  other_public_key_path, device_path);
    return 0;
}
