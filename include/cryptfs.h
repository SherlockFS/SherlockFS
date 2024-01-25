#ifndef CRYPT_FS_H
#define CRYPT_FS_H

#include <stdint.h>

#include "block.h"
#include "error.h"

// -----------------------------------------------------------------------------
// HEADER SECTION
// -----------------------------------------------------------------------------
#define CRYPTFS_BOOT_SECTION_SIZE_BYTES 5
#define CRYPTFS_MAGIC 0x63727970746673
#define CRYPTFS_VERSION 1
#define CRYPTFS_BLOCK_SIZE_BYTES 512
#define CRYPTFS_BLOCK_SIZE_BITS (CRYPTFS_BLOCK_SIZE_BYTES * 8)

/**
 * @brief HEADER (block 0) of the filesystem.
 *
 * The header is the first block of the filesystem. It contains fields that
 * describe the filesystem (magic number, version, block size, ...).
 */
struct CryptFS_Header
{
    uint8_t boot[CRYPTFS_BOOT_SECTION_SIZE_BYTES]; // Reserved for boot code
                                                   // (bootloader, etc.)
    uint64_t magic; // CRYPTFS_MAGIC
    uint8_t version; // CRYPTFS_VERSION
    uint32_t blocksize; // in bytes
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

// -----------------------------------------------------------------------------
// KEYS STORAGE SECTION
// -----------------------------------------------------------------------------

#define NB_ENCRYPTION_KEYS 64

#define RSA_KEY_SIZE_BITS 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE_BITS / 8)

#define AES_KEY_SIZE_BITS 256
#define AES_KEY_SIZE_BYTES (AES_KEY_SIZE_BITS / 8)

/**
 * @brief Structure that contains a key used to encrypt/decrypt the filesystem.
 *
 * The key used to encrypt/decrypt the filesystem is an AES key. This key is
 * encrypted with the RSA public key of the user.
 *
 * @note An RSA public key is a pair of big integers (n and e). Because the
 * number e is always the same (RSA_EXPONENT), only the number n is stored in
 * the structure.
 */
struct CryptFS_KeySlot
{
    uint8_t rsa_n[RSA_KEY_SIZE_BYTES]; // RSA public number 'n' (the modulus)
    uint8_t aes_key_ciphered[RSA_KEY_SIZE_BYTES]; // AES key ciphered with RSA
                                                  // public key
} __attribute__((packed));

// -----------------------------------------------------------------------------
// FAT (File Allocation Table) SECTION
// -----------------------------------------------------------------------------

/**
 * @brief Structure that contains a FAT (File Allocation Table) entry.
 *
 * Each FAT entry is used to store the index of the next block in the FAT
 * linked- list.
 *
 * @example If a file is a size of 4 blocks, and starts at block 5, the FAT
 * chain can be: 5 -> 34 -> 42 -> 24 -> 20 -> FAT_BLOCK_END.
 */
struct CryptFS_FAT_Entry
{
    uint32_t next_block; // Next block in the FAT chain
} __attribute__((packed));

/**
 * @brief Structure that contains a FAT (File Allocation Table) block.
 *
 * A FAT block is a linked-list of FAT entries.
 *
 * @note The value FAT_BLOCK_END is used to mark the end of the FAT chain.
 * @example If on the block 42, the next block is FAT_BLOCK_END, the file is
 * finished.
 *
 * @link https://en.wikipedia.org/wiki/File_Allocation_Table
 */
struct CryptFS_FAT
{
    uint64_t next_fat_table; // Next FAT table in the FAT chain
    struct CryptFS_FAT_Entry entries[]; // FAT entries
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

#define NB_FAT_ENTRIES_PER_BLOCK                                               \
    ((CRYPTFS_BLOCK_SIZE_BYTES - sizeof(uint64_t))                             \
     / sizeof(struct CryptFS_FAT_Entry))

enum FAT_BLOCK_TYPE
{
    FAT_BLOCK_END = -2, // End of file.
    FAT_BLOCK_ERROR = -1, // Error related to FAT. (Never written in any FAT)
    FAT_BLOCK_FREE = 0, // The block is free.
};

// -----------------------------------------------------------------------------
// (ROOT) DIRECTORY SECTION
// -----------------------------------------------------------------------------

#define ENTRY_NAME_MAX_LEN 128

enum ENTRY_TYPE
{
    ENTRY_TYPE_FILE = 0,
    ENTRY_TYPE_DIRECTORY = 1,
    ENTRY_TYPE_HARDLINK = 2,
    ENTRY_TYPE_SYMLINK = 3,
    ENTRY_TYPE_UNKNOWN = 4
};

/**
 * @brief Structure that contains an entry (file, directory, link, ...).
 *
 * This structure contains all the metadata of an entry (size, name,
 * permissions, ...).
 */
struct CryptFS_Entry
{
    uint8_t used; // 1 if the directory is used, 0 if free
    uint8_t type; // ENTRY_TYPE
    uint64_t
        start_block; // First block of the entry, FAT_BLOCK_END for directory
    char name[ENTRY_NAME_MAX_LEN]; // Name of the entry
    uint64_t size; // in bytes
    uint32_t uid; // User ID
    uint32_t gid; // Group ID
    uint32_t mode; // Permissions (Unix-like)
    uint32_t atime; // Access time
    uint32_t mtime; // Modification time
    uint32_t ctime; // Creation time
} __attribute__((packed));

/**
 * @brief Structure that describes a directory.
 *
 * A directory contains entries (files, links, other directories, ...).
 */
struct CryptFS_Directory
{
    uint32_t num_entries;
    struct CryptFS_Entry entries[];
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

#define CRYPTFS_MAX_ENTRIES_PER_DIR (CRYPTFS_BLOCK_SIZE_BYTES - sizeof(uint8_t) - sizeof(uint32_t)) / sizeof(struct CryptFS_Entry))

// -----------------------------------------------------------------------------
// FILE CONTENT DATA
// -----------------------------------------------------------------------------
typedef char f_cont_t; // File content type

// -----------------------------------------------------------------------------
// CRYPTFS FILE SYSTEM
// -----------------------------------------------------------------------------
#define HEADER_BLOCK 0
#define KEYS_STORAGE_BLOCK 1
#define FIRST_FAT_BLOCK 65
#define ROOT_DIR_BLOCK 66

struct CryptFS
{
    struct CryptFS_Header header; // BLOCK 0: Header
    struct CryptFS_KeySlot keys_storage[NB_ENCRYPTION_KEYS]; // BLOCK 1-64: Keys
    struct CryptFS_FAT first_fat; // BLOCK 65: First FAT
    struct CryptFS_Directory root_directory; // BLOCK 66: Root directory
};

#endif /* CRYPT_FS_H */
