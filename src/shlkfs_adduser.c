#include <stdio.h>
#include <stdlib.h>

#include "adduser.h"
#include "cryptfs.h"
#include "crypto.h"

int main(int argc, char *argv[])
{
    char *device_path = NULL;
    char *other_public_key_path = NULL;
    char *my_private_key_path = NULL;

    switch (argc)
    {
    case 3: // <device> <other user public key path>
        device_path = argv[1];
        other_public_key_path = argv[2];

        char *useless_my_public_key_path = NULL;
        get_rsa_keys_home_paths(&useless_my_public_key_path,
                                &my_private_key_path);
        free(useless_my_public_key_path);

        break;
    case 4: // <device> <other user public key path> <my private key path>
        device_path = argv[1];
        other_public_key_path = argv[2];
        my_private_key_path = argv[3];
        break;
    default:
        printf("SherlockFS v%d - Adding user to device keys storage\n",
               CRYPTFS_VERSION);
        printf("\tUsage: %s <device> <other user public key path> [<registred "
               "user private key path>]\n",
               argv[0]);
        return EXIT_FAILURE;
    }

    cryptfs_adduser(device_path, other_public_key_path, my_private_key_path);

    if (argc == 3) // if `my_private_key_path` was malloced
        free(my_private_key_path);

    return EXIT_SUCCESS;
}
