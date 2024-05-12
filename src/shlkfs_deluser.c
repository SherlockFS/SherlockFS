#include <stdio.h>
#include <stdlib.h>

#include "cryptfs.h"
#include "crypto.h"
#include "deluser.h"

int main(int argc, char *argv[])
{
    char *device_path = NULL;
    char *deleting_user_public_key_path = NULL;
    char *my_private_key_path = NULL;

    switch (argc)
    {
    case 3: // <device> <other user public key path> [my private key path]
        device_path = argv[1];
        deleting_user_public_key_path = argv[2];
        get_rsa_keys_home_paths(NULL, &my_private_key_path);
        break;
    case 4: // <device> <other user public key path> <my private key path>
        device_path = argv[1];
        deleting_user_public_key_path = argv[2];
        my_private_key_path = argv[3];
        break;
    default:
        printf("SherlockFS v%d - Deleting user from device keys storage\n",
               CRYPTFS_VERSION);
        printf("\tUsage: %s <device> <deleting user public key path> "
               "[registred user private key path]\n",
               argv[0]);
        return EXIT_FAILURE;
    }

    int ret = cryptfs_deluser(device_path, my_private_key_path,
                              deleting_user_public_key_path);
    if (argc == 3)
        free(my_private_key_path);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
