#include <stdio.h>

#include "cryptfs.h"
#include "crypto.h"
#include "print.h"
#include "xalloc.h"

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <device> <mountpoint>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *device_path = argv[1], *mount_path = argv[2];
    (void)mount_path;

    // Load the RSA keypair from the user's home directory
    char *passphrase = NULL;
    EVP_PKEY *rsa_key = load_rsa_keypair_from_home(&passphrase);

    // Read the header of the device
    FILE *device_file = fopen(device_path, "r");
    if (!device_file)
        error_exit("Impossible to open the device file\n", EXIT_FAILURE);

    struct CryptFS_Header header = { 0 };
    if (fread(&header, sizeof(struct CryptFS_Header), 1, device_file) != 1)
        error_exit("Impossible to read the header\n", EXIT_FAILURE);

    fclose(device_file);

    // Set the file system global variables
    set_device_path(device_path);
    set_block_size(header.blocksize);

    // Read the keys storage from the device
    struct CryptFS_Key *keys_storage =
        xcalloc(NB_ENCRYPTION_KEYS, get_block_size());

    read_blocks(KEYS_STORAGE_BLOCK, NB_ENCRYPTION_KEYS, keys_storage);

    // Searching for a legitimate key
    int8_t matching_rsa_index = find_rsa_matching_key(rsa_key, keys_storage);
    if (matching_rsa_index == -1)
    {
        print_error("You are not allowed to access this encrypted device\n");
        error_exit("No matching RSA key found\n", EXIT_FAILURE);
    }

    // Free the memory
    EVP_PKEY_free(rsa_key);
    free(keys_storage);
    free(passphrase);

    // mount the decrypted data using the key
    return 0;
}
