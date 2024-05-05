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
    .write = cryptfs_write,
    .release = cryptfs_release,
    .opendir = cryptfs_opendir,
    .releasedir = cryptfs_releasedir,
    .mkdir = cryptfs_mkdir,
    .mknod = cryptfs_mknod,
    .rmdir = cryptfs_rmdir,
    .unlink = cryptfs_unlink,
    .rename = cryptfs_rename,
    .chmod = cryptfs_chmod,
    .chown = cryptfs_chown,
    .truncate = cryptfs_truncate,
    .utime = cryptfs_utime,
    .create = cryptfs_create,
    .access = cryptfs_access,
    .link = cryptfs_link,
    .symlink = cryptfs_symlink,
    .readlink = cryptfs_readlink,
    .statfs = cryptfs_statfs,
    .flush = cryptfs_flush,
    .fsync = cryptfs_fsync,
    .setxattr = cryptfs_setxattr,
    .getxattr = cryptfs_getxattr,
    .listxattr = cryptfs_listxattr,
    .removexattr = cryptfs_removexattr,
    .fallocate = cryptfs_fallocate,
    .lock = cryptfs_lock,
    .bmap = cryptfs_bmap,
    .ioctl = cryptfs_ioctl,
    .poll = cryptfs_poll,
    .write_buf = NULL, // Low level funcion use with splice
    .read_buf = NULL, // Low level funcion use with splice
    .flock = cryptfs_flock,
    .ftruncate = cryptfs_ftruncate,
    .destroy = cryptfs_destroy,
};

// Parser grammar
#define IS_USING_K_ARG(argv)                                                   \
    ((strcmp(*(argv), "-k") == 0 || strcmp(*(argv), "--key") == 0)             \
     && *(argv + 1) != NULL)
#define IS_USING_V_ARG(argv)                                                   \
    (strcmp(*(argv), "-v") == 0 || strcmp(*(argv), "--verbose") == 0)

#define IS_USING_SHLK_ARG(argv) (IS_USING_K_ARG(argv) || IS_USING_V_ARG(argv))

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("SherlockFS v%d - Mounting a SherlockFS file system\n",
               CRYPTFS_VERSION);
        printf("\tUsage: %s [-k|--key <PRIVATE KEY PATH>] [-v|--verbose] "
               "<DEVICE> [FUSE "
               "OPTIONS] <MOUNTPOINT>\n",
               argv[0]);
        return EXIT_FAILURE;
    }

    // Private RSA key path
    char *private_key_path = NULL;

    // Saving program name
    char **new_argv = xcalloc(argc, sizeof(char *));
    new_argv[0] = argv[0];
    argv++; // skip the program name
    argc--; // sub the program name
    while (*argv && IS_USING_SHLK_ARG(argv))
    {
        // if '-k' option is provided, use this RSA to decrypt master key
        if (IS_USING_K_ARG(argv))
        {
            private_key_path = argv[1];
            argv += 2; // skip '-k' and private key path
            argc -= 2; // sub '-k' and private key path
        }
        // if '-v' or '--debug' option is provided, set the verbosity level
        else if (IS_USING_V_ARG(argv))
        {
            set_verbosity_level(PRINT_LEVEL_DEBUG);
            argv += 1; // skip '-v' or '--debug'
            argc -= 1; // sub '-v' or '--debug'
        }
    }

    // Copy the rest of the arguments
    for (int i = 1; i < argc; i++)
        new_argv[i] = argv[i];

    const char *device_path = argv[0];

    // Set the file system global variables
    set_device_path(device_path);

    print_info("Checking if the device '%s' is a SherlockFS device...\n",
               device_path);
    if (!is_already_formatted(device_path))
    {
        error_exit(
            "The device '%s' is not formatted. Please format it first.\n",
            EXIT_FAILURE, device_path);
    }

    // If the private key path is not provided, get it from the RSA keys home
    if (private_key_path == NULL)
        get_rsa_keys_home_paths(NULL, &private_key_path);

    fpi_register_master_key_from_path(device_path, private_key_path);

    int ret = fuse_main(argc, new_argv, &ops, NULL);
    if (ret == 0)
        print_success("SherlockFS instance exited successfully.\n");
    else
        print_error("SherlockFS instance exited with an error: '%s'\n",
                    strerror(ret));

    free(new_argv);
    return ret;
}
