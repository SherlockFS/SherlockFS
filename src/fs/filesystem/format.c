#include "format.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "print.h"
#include "xalloc.h"

bool is_already_formatted(const char *file_path)
{
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
        return false;

    struct CryptFS_Header header = { 0 };

    fread(&header, sizeof(header), 1, file);

    fclose(file);

    // Check if the magic number is correct
    if (header.magic != CRYPTFS_MAGIC)
        return false;
    // Check if the version is correct
    else if (header.version != CRYPTFS_VERSION)
        return false;
    // Check if the blocksize is correct (must be a multiple of 2)
    else if (header.blocksize == 0 || header.blocksize % 2 != 0)
        return false;

    return true;
}

void format_fill_filesystem_struct(struct CryptFS *cfs, char *rsa_passphrase,
                                   const EVP_PKEY *existing_rsa_keypair,
                                   const char *public_key_path,
                                   const char *private_key_path)
{
    /// ------------------------------------------------------------
    /// BLOCK 0 : HEADER
    /// ------------------------------------------------------------

    // Craft the header
    cfs->header.magic = CRYPTFS_MAGIC;
    cfs->header.version = CRYPTFS_VERSION;
    cfs->header.blocksize = CRYPTFS_BLOCK_SIZE_BYTES;

    for (size_t i = 0; i < CRYPTFS_BOOT_SECTION_SIZE_BYTES; i++)
        cfs->header.boot[i] = 0x90; // NOP sled

    /// ------------------------------------------------------------
    /// BLOCK 1 : KEYS STORAGE
    /// ------------------------------------------------------------

    // Generate AES + RSA keys
    unsigned char *aes_key = generate_aes_key();

    EVP_PKEY *rsa_key = NULL;
    if (existing_rsa_keypair != NULL)
        rsa_key = EVP_PKEY_dup((EVP_PKEY *)existing_rsa_keypair);
    else
        rsa_key = generate_rsa_keypair();

    // Store the RSA modulus and the RSA public exponent in the header
    store_keys_in_keys_storage(cfs->keys_storage, rsa_key, aes_key);

    // If the user provided a custom path for the keys
    if (public_key_path && private_key_path)
        write_rsa_keys_on_disk(rsa_key, public_key_path, private_key_path,
                               rsa_passphrase);
    else
    {
        char *user_dir_path = getenv("HOME");
        if (!user_dir_path)
            internal_error_exit("Impossible to get the user directory path\n",
                                EXIT_FAILURE);

        // Add .cryptfs to the user directory path
        char *public_key_path = xcalloc(PATH_MAX, sizeof(char));
        char *private_key_path = xcalloc(PATH_MAX, sizeof(char));

        strcat(public_key_path, user_dir_path);
        strcat(public_key_path, "/.cryptfs");

        // Create the directories
        if (mkdir(public_key_path, 0755) != 0 && errno != EEXIST)
            internal_error_exit("Failed to create the directories\n",
                                EXIT_FAILURE);

        strcat(public_key_path, "/public.pem");

        strcat(private_key_path, user_dir_path);
        strcat(private_key_path, "/.cryptfs/private.pem");

        // Write the RSA public and private keys in ~/.cryptfs/
        write_rsa_keys_on_disk(rsa_key, public_key_path, private_key_path,
                               rsa_passphrase);

        free(public_key_path);
        free(private_key_path);
    }
    /// ------------------------------------------------------------
    /// BLOCK 2 : FAT (File Allocation Table)
    /// ------------------------------------------------------------

    cfs->first_fat.next_fat_table = FAT_BLOCK_END;
    for (size_t i = 0; i <= ROOT_DIR_BLOCK; i++)
        write_fat_offset(&cfs->first_fat, i, FAT_BLOCK_END);

    /// ------------------------------------------------------------
    /// BLOCK 3 : ROOT DIRECTORY
    /// ------------------------------------------------------------
    //// Noting to add

    free(aes_key);
    EVP_PKEY_free(rsa_key);
}

void format_fs(const char *path, char *public_key_path, char *private_key_path,
               char *rsa_passphrase, EVP_PKEY *existing_rsa_keypair)
{
    struct CryptFS *cfs = xcalloc(1, sizeof(struct CryptFS));

    set_block_size(CRYPTFS_BLOCK_SIZE_BYTES);
    set_device_path(path);

    format_fill_filesystem_struct(cfs, rsa_passphrase, existing_rsa_keypair,
                                  public_key_path, private_key_path);

    FILE *file = fopen(path, "w+");
    if (file == NULL)
        error_exit("Impossible to open the fill\n", EXIT_FAILURE);

    // Write the filesystem structure on the disk
    print_info("Writing the filesystem structure on the disk...\n");
    if (fwrite(cfs, sizeof(*cfs), 1, file) != 1)
        error_exit("Impossible to write the filesystem structure\n",
                   EXIT_FAILURE);

    free(cfs);

    fclose(file);
}

bool keypair_in_home_exist(void)
{
    char *public_path = NULL;
    char *private_path = NULL;

    get_rsa_keys_home_paths(&public_path, &private_path);

    bool exist =
        access(private_path, F_OK) == 0 && access(public_path, F_OK) == 0;

    free(public_path);
    free(private_path);

    return exist;
}
