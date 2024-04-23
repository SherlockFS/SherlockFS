#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "format.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "stdlib.h"
#include "xalloc.h"

static struct fuse_operations ops = {
    .init = cryptfs_init,
    .getattr = cryptfs_getattr,
    .readdir = cryptfs_readdir,
    .open = cryptfs_open,
    .read = cryptfs_read,
};
#define K_PARAM_POS 1
#define K_VALUE_POS (K_PARAM_POS + 1)
#define IS_USING_K_ARG(argc, argv)                                             \
    (argc >= K_VALUE_POS && strcmp(argv[K_PARAM_POS], "-k") == 0)

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("SherlockFS v%d - Mounting SherlockFS file system\n",
               CRYPTFS_VERSION);
        printf("Usage: %s [-k <PRIVATE KEY PATH>] <DEVICE> [FUSE "
               "OPTIONS] MOUNTPOINT\n",
               argv[0]);
        return EXIT_FAILURE;
    }
    const char *device_path = argv[1];

    // Set the file system global variables
    set_device_path(device_path);

    print_info("Checking if the device is a SherlockFS device...\n");
    if (!is_already_formatted(device_path))
    {
        error_exit(
            "The device '%s' is not formatted. Please format it first.\n",
            EXIT_FAILURE, device_path);
    }

    // Get the RSA private key from the arguments (if provided)
    char *private_key_path = NULL;
    if (IS_USING_K_ARG(argc, argv))
    {
        private_key_path = argv[4];
    }
    else
    {
        // Get the RSA keys home paths (public and private).
        get_rsa_keys_home_paths(NULL, &private_key_path);
    }

    char *passphrase = NULL;

    // Check if my private key is encrypted
    if (rsa_private_is_encrypted(private_key_path))
        passphrase = ask_user_passphrase(false);

    // Extract the aes_key
    print_info("Extracting master key from the device...\n");
    unsigned char *aes_key =
        extract_aes_key(device_path, private_key_path, passphrase);

    print_info("Mounting SherlockFS file system...\n");

    // Register the master key
    fpi_set_master_key(aes_key);

    // argv(0) -> new_argv[0]
    // argv(<mountpoint>) -> new_argv[1]

    // if '-k' option is provided, skip it and the private key path
    char **new_argv = xcalloc(argc, sizeof(char *));
    new_argv[0] = argv[0];
    if (IS_USING_K_ARG(argc, argv))
    {
        for (int i = 4; i < argc; i++) // pgrm, -k, pkey, device, mountpoint
            new_argv[i - 4 + 1] = argv[i];
        argc -= 3; // sub -k, pkey, device
    }
    else
    {
        for (int i = 2; i < argc; i++)
            new_argv[i - 2 + 1] = argv[i]; // pgrm, device, mountpoint
        argc -= 1; // sub device
    }

    // Start FUSE
    free(aes_key);
    if (passphrase != NULL)
        free(passphrase);

    int ret = fuse_main(argc, new_argv, &ops, NULL);
    print_info("Exiting SherlockFS process...\n");
    return ret;
}
