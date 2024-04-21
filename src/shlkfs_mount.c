#include "mount.h"
#include "cryptfs.h"
#include "crypto.h"
#include "print.h"
#include "xalloc.h"
#include "readfs.h"
#include "format.h"
#include "fat.h"
#include "stdlib.h"


int main(int argc, char *argv[])
{
    int ret;

    if (argc < 3)
    {
        printf("Usage: %s <mountpoint> <device>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *device_path = argv[argc-1], *mount_path = argv[argc-2];

    (void)mount_path;



    printf("DEVICE PATH IS %s\n", device_path);
    // Set the file system global variables
    set_device_path(device_path);

//     Get the RSA keys home paths (public and private).
    char *public_path = NULL;
    char *private_key_path = NULL;
    get_rsa_keys_home_paths(&public_path, &private_key_path);

    // Extract the aes_key
    unsigned char *aes_key = extract_aes_key(device_path, private_key_path);

    // mount the decrypted data using the key
    // Remove the device argument for fuse
    argv[argc--] = NULL;

    // Start FUSE
    ret = start_fuse(aes_key, argc, argv);
    free(aes_key);
    return ret;
}
