#include "fuse_ps_info.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cryptfs.h"
#include "crypto.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "xalloc.h"

// ------------------- File system information management -------------------

struct fs_ps_info
{
    bool master_key_set; // Whether the master key has been set
    unsigned char master_key[AES_KEY_SIZE_BYTES]; // XORed AES master key
    unsigned char xor_key[AES_KEY_SIZE_BYTES]; // master key XOR key
    unsigned char decoded_key[AES_KEY_SIZE_BYTES]; // Decoded key (must be
                                                   // zeroed after use)
    block_t current_directory_block; // Current directory block number
} __attribute__((packed));

static struct fs_ps_info info = {
    .master_key_set = false,
    .master_key = { 0 },
    .xor_key = { 0 },
    .decoded_key = { 0 },
    .current_directory_block = ROOT_ENTRY_BLOCK,
};

void fpi_register_master_key_from_path(const char *device_path,
                                       const char *private_key_path)
{
    char *passphrase = NULL;

    // Check if my private key is encrypted
    if (rsa_private_is_encrypted(private_key_path))
        passphrase = ask_user_passphrase(false);

    // Check if the private key is registered in the device
    // Loading the user public key from disk in memory
    print_info("Loading private key '%s' from disk...\n", private_key_path);
    EVP_PKEY *my_rsa = load_rsa_keypair_from_disk(NULL, private_key_path, NULL);

    // Find matching RSA key in the keys storage
    struct CryptFS *cryptfs = read_cryptfs_headers(device_path);

    // Check if other user is already in the keys storage
    ssize_t index = find_rsa_matching_key(my_rsa, cryptfs->keys_storage);
    free(cryptfs);
    EVP_PKEY_free(my_rsa);
    if (index == -1)
        error_exit(
            "The user with the private key '%s' is not registred in the keys "
            "storage of the device '%s'\n",
            EXIT_FAILURE, private_key_path, device_path);

    // Extract the aes_key
    print_info("Extracting master key from the device...\n");
    unsigned char *aes_key =
        extract_aes_key(device_path, private_key_path, passphrase);

    // Register the master key
    fpi_register_master_key(aes_key);

    free(aes_key);
    if (passphrase != NULL)
        free(passphrase);
}

void fpi_register_master_key(unsigned char *key)
{
    info.master_key_set = true;
    srand(time(NULL)); // Basic seed for random number generation, but
                       // acceptable for memory resilience

    for (int i = 0; i < AES_KEY_SIZE_BYTES; i++)
    {
        info.xor_key[i] = rand() % 0xFF; // Generate a random XOR key
        info.master_key[i] = key[i] ^ info.xor_key[i]; // Store the XOR'd key
    }

    // Erase the key from memory
    memset(key, 0, AES_KEY_SIZE_BYTES);
}

const unsigned char *fpi_get_master_key()
{
    if (!info.master_key_set)
        return NULL;

    for (int i = 0; i < AES_KEY_SIZE_BYTES; i++)
        info.decoded_key[i] = info.master_key[i]
            ^ info.xor_key[i]; // Decode the key before returning it

    return info.decoded_key; // ! Careful, the key must be zeroed after use
                             // using fpi_clear_decoded_key()
}

void fpi_clear_decoded_key()
{
    memset(info.decoded_key, 0, AES_KEY_SIZE_BYTES);
}

void fpi_set_current_directory_block(block_t block)
{
    info.current_directory_block = block;
}

block_t fpi_get_current_directory_block()
{
    return info.current_directory_block;
}
