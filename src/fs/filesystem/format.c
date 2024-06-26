#include "format.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "fat.h"
#include "maths.h"
#include "print.h"
#include "xalloc.h"

bool is_already_formatted(const char *device_path)
{
    FILE *file = fopen(device_path, "r");
    if (file == NULL)
        return false;

    struct CryptFS_Header header = { 0 };

    fread(&header, sizeof(header), 1, file);

    fclose(file);

    // Check if the magic number is correct
    if (strncmp((char *)header.magic, CRYPTFS_MAGIC, CRYPTFS_MAGIC_SIZE) != 0)
        return false;
    // Check if the version is correct
    else if (header.version != CRYPTFS_VERSION)
    {
        print_error("Implementation not supported\n");
        return false;
    }
    // Check if the blocksize is exactly CRYPTFS_BLOCK_SIZE_BYTES
    // (the only supported block size in this implementation)
    else if (header.blocksize != CRYPTFS_BLOCK_SIZE_BYTES)
    {
        print_error("The size '%d' is not supported in this implementation\n",
                    header.blocksize);
        return false;
    }

    return true;
}

void format_fill_filesystem_struct(struct CryptFS *shlkfs, const char *label,
                                   char *rsa_passphrase,
                                   EVP_PKEY *existing_rsa_keypair,
                                   const char *public_key_path,
                                   const char *private_key_path)
{
    /// ------------------------------------------------------------
    /// BLOCK 0 : HEADER
    /// ------------------------------------------------------------

    // Craft the header
    memcpy((char *)shlkfs->header.magic, CRYPTFS_MAGIC, CRYPTFS_MAGIC_SIZE);
    shlkfs->header.version = CRYPTFS_VERSION;
    shlkfs->header.blocksize = CRYPTFS_BLOCK_SIZE_BYTES;
    if (label)
        memcpy((char *)shlkfs->header.label, label,
               MIN(strlen(label), CRYPTFS_LABEL_SIZE));
    shlkfs->header.last_fat_block = FIRST_FAT_BLOCK;

    for (size_t i = 0; i < CRYPTFS_BOOT_SECTION_SIZE_BYTES; i++)
        shlkfs->header.boot[i] = 0x90; // NOP sled

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
    store_keys_in_keys_storage(shlkfs->keys_storage, rsa_key, aes_key);

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

        // Add .shlkfs to the user directory path
        char *public_key_path = xcalloc(PATH_MAX, sizeof(char));
        char *private_key_path = xcalloc(PATH_MAX, sizeof(char));

        strcat(public_key_path, user_dir_path);
        strcat(public_key_path, "/.shlkfs");

        // Create the directories
        if (mkdir(public_key_path, 0755) != 0 && errno != EEXIST)
            internal_error_exit("Failed to create the directories\n",
                                EXIT_FAILURE);

        strcat(public_key_path, "/public.pem");

        strcat(private_key_path, user_dir_path);
        strcat(private_key_path, "/.shlkfs/private.pem");

        // Write the RSA public and private keys in ~/.shlkfs/
        write_rsa_keys_on_disk(rsa_key, public_key_path, private_key_path,
                               rsa_passphrase);

        free(public_key_path);
        free(private_key_path);
    }
    /// ------------------------------------------------------------
    /// BLOCK 2 : FAT (File Allocation Table)
    /// ------------------------------------------------------------

    shlkfs->first_fat.next_fat_table = BLOCK_END;
    for (size_t i = 0; i <= ROOT_DIR_BLOCK; i++)
        shlkfs->first_fat.entries[i].next_block = BLOCK_END;

    /// ------------------------------------------------------------
    /// BLOCK 3 : ROOT DIRECTORY ENTRY
    /// ------------------------------------------------------------

    // Add an entry at ROOT_ENTRY_BLOCK for the root directory
    uint32_t creation_time = time(NULL);

    shlkfs->root_entry.used = 1;
    shlkfs->root_entry.type = ENTRY_TYPE_DIRECTORY;
    shlkfs->root_entry.start_block = ROOT_DIR_BLOCK;
    shlkfs->root_entry.uid = getuid();
    shlkfs->root_entry.gid = getgid();
    shlkfs->root_entry.mode = 0777;
    shlkfs->root_entry.ctime = creation_time;
    shlkfs->root_entry.mtime = creation_time;
    shlkfs->root_entry.atime = creation_time;
    shlkfs->root_entry.nlink = 1;
    strcpy(shlkfs->root_entry.name, "");

    /// ------------------------------------------------------------
    /// BLOCK 4 : ROOT DIRECTORY DIRECTORY
    /// ------------------------------------------------------------
    shlkfs->root_directory.current_directory_entry.directory_block =
        ROOT_ENTRY_BLOCK;
    shlkfs->root_directory.current_directory_entry.directory_index = 0;

    /// ------------------------------------------------------------
    /// Encrypting FAT and ROOT DIRECTORY with AES
    /// ------------------------------------------------------------
    size_t encrypted_fat_size = 0;
    unsigned char *encrypted_fat =
        aes_encrypt_data(aes_key, &shlkfs->first_fat, CRYPTFS_BLOCK_SIZE_BYTES,
                         &encrypted_fat_size);
    memset(&shlkfs->first_fat, 0, CRYPTFS_BLOCK_SIZE_BYTES);
    memcpy(&shlkfs->first_fat, encrypted_fat, encrypted_fat_size);

    size_t encrypted_entry_size;
    unsigned char *encrypted_root_dir =
        aes_encrypt_data(aes_key, &shlkfs->root_entry, CRYPTFS_BLOCK_SIZE_BYTES,
                         &encrypted_entry_size);
    memset(&shlkfs->root_entry, 0, CRYPTFS_BLOCK_SIZE_BYTES);
    memcpy(&shlkfs->root_entry, encrypted_root_dir, encrypted_entry_size);

    size_t encrypted_root_dir_size;
    unsigned char *encrypted_root_directory =
        aes_encrypt_data(aes_key, &shlkfs->root_directory,
                         CRYPTFS_BLOCK_SIZE_BYTES, &encrypted_root_dir_size);
    memset(&shlkfs->root_directory, 0, CRYPTFS_BLOCK_SIZE_BYTES);
    memcpy(&shlkfs->root_directory, encrypted_root_directory,
           encrypted_root_dir_size);

    free(aes_key);
    EVP_PKEY_free(rsa_key);
    free(encrypted_fat);
    free(encrypted_root_dir);
    free(encrypted_root_directory);
}

void format_fs(const char *path, char *public_key_path, char *private_key_path,
               const char *label, char *rsa_passphrase,
               EVP_PKEY *existing_rsa_keypair)
{
    struct CryptFS *shlkfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));

    set_device_path(path);

    format_fill_filesystem_struct(shlkfs, label, rsa_passphrase,
                                  existing_rsa_keypair, public_key_path,
                                  private_key_path);

    FILE *file = fopen(path, "r+");
    if (file == NULL)
        error_exit("Impossible to open the fill\n", EXIT_FAILURE);

    // Write the filesystem structure on the disk
    print_info("Writing the filesystem structure on the device...\n");
    if (fwrite(shlkfs, sizeof(*shlkfs), 1, file) != 1)
        error_exit("Impossible to write the filesystem structure\n",
                   EXIT_FAILURE);

    free(shlkfs);
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
