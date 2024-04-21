#ifndef CRYPT_FS_H
#define CRYPT_FS_H

#include <openssl/sha.h>
#include <stdint.h>

#include "block.h"
#include "error.h"

// -----------------------------------------------------------------------------
// HEADER SECTION
// -----------------------------------------------------------------------------
#define CRYPTFS_BOOT_SECTION_SIZE_BYTES 1024
#define CRYPTFS_MAGIC 0x63727970746673
#define CRYPTFS_VERSION 1
#define CRYPTFS_BLOCK_SIZE_BYTES 4096
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
    uint64_t device_size; // in bytes
    uint64_t last_fat_block; // Last FAT block index
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
 */
struct CryptFS_KeySlot
{
    uint8_t occupied; // 1 if the slot is occupied, 0 if free
    uint8_t aes_key_ciphered[RSA_KEY_SIZE_BYTES]; // AES key ciphered with RSA
    uint8_t rsa_n[RSA_KEY_SIZE_BYTES]; // RSA public modulus 'n'
    uint32_t rsa_e; // RSA public exponent 'e' (big endian)
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

// -----------------------------------------------------------------------------
// FAT (File Allocation Table) SECTION
// -----------------------------------------------------------------------------

/**
 * @brief Structure that contains a FAT (File Allocation Table) entry.
 *
 * Each FAT entry is used to store the index of the next block in the FAT
 * linked- list.
 *
 * @example If a file/directory is a size of 4 blocks, and starts at block 5,
 * the FAT chain can be: 5 -> 34 -> 42 -> 24 -> 20 -> BLOCK_END.
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
 * @note The value BLOCK_END is used to mark the end of the FAT chain.
 * @example If on the block 42, the next block is BLOCK_END, the file is
 * finished.
 *
 * @link https://en.wikipedia.org/wiki/File_Allocation_Table
 */
struct CryptFS_FAT
{
    uint64_t next_fat_table; // Next FAT table block in the FAT chain
    struct CryptFS_FAT_Entry entries[]; // FAT entries
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

#define NB_FAT_ENTRIES_PER_BLOCK                                               \
    ((CRYPTFS_BLOCK_SIZE_BYTES - sizeof(uint64_t))                             \
     / sizeof(struct CryptFS_FAT_Entry))

enum BLOCK_TYPE
{
    BLOCK_FAT_OOB = -3, // FAT index is out of band
    BLOCK_ERROR = -2, // Error related to blocks. (Never written on the device)
    BLOCK_END = -1, // End of entity.
    BLOCK_FREE = 0, // The block is free.
};

// -----------------------------------------------------------------------------
// (ROOT) DIRECTORY SECTION
// -----------------------------------------------------------------------------

#define ENTRY_NAME_MAX_LEN 128

enum ENTRY_TYPE
{
    ENTRY_TYPE_FILE = 0, // start_block -> blob
    ENTRY_TYPE_DIRECTORY = 1, // start_block -> struct CryptFS_Directory
    ENTRY_TYPE_HARDLINK = 2, // start_block -> same blob
    ENTRY_TYPE_SYMLINK = 3 // start_block -> a block which contains a string
};

/**
 * @brief Structure that contains an entry (file, directory, link, ...).
 *
 * This structure contains all the metadata of an entry (size, name,
 * permissions, ...).
 *
 * @details DIRECTORY:
 * A directory contains entries (files, links, other directories, ...).
 *
 * The start_block of a directory entry points to a block that contains a
 * contiguous list of entries. The number of entries that can be stored in one
 * block is defined by the macro NB_ENTRIES_PER_BLOCK. Of course, it's important
 * to relate to FAT entries. For example, if a directory has a size of 26, which
 * means it contains 26 entries, which also means 2 entries more than the number
 * of entries that can be stored in a block (for a block size of 4096 bytes),
 * then the directory will be stored in 2 blocks.
 *
 * @details FILE:
 * A file contains a blob of data. The start_block of a file entry points to the
 * first block of the blob. The size of the blob is the size of the entry. The
 * file may be trucated in multiple blocks. Thus, it's important to relate to
 * FAT entries.
 *
 * @details HARDLINK:
 * A hardlink is a reference to another entry. The start_block of a hardlink
 * entry points to the same blob as the entry it references and its size is the
 * size of the entry it references.
 *
 * @details SYMLINK:
 * A symlink is a reference to a string. The start_block of a symlink entry
 * points to a block that contains a string. The string is the path of the
 * target. The size of the string is the size of the entry. The string is NOT
 * NUL terminated. The string may be trucated in multiple blocks. Thus, it's
 * important to relate to FAT entries.
 */
struct CryptFS_Entry
{
    uint8_t used; // 1 if the directory is used, 0 if free
    uint8_t type; // ENTRY_TYPE
    uint64_t start_block; // First block of the entry
    char name[ENTRY_NAME_MAX_LEN]; // Name of the entry
    uint64_t size; // in number of entries for directories, in bytes for others
    uint32_t uid; // User ID
    uint32_t gid; // Group ID
    uint32_t mode; // Permissions (Unix-like)
    uint32_t atime; // Access time
    uint32_t mtime; // Modification time
    uint32_t ctime; // Creation time
} __attribute__((packed));

struct CryptFS_Entry_ID
{
    block_t directory_block; // The block number to struct CryptFS_Directory.
    uint32_t directory_index; // Index of the Directory entry in the directory.
} __attribute__((packed));

#define NB_ENTRIES_PER_BLOCK                                                   \
    ((CRYPTFS_BLOCK_SIZE_BYTES - sizeof(struct CryptFS_Entry_ID))              \
     / sizeof(struct CryptFS_Entry))

struct CryptFS_Directory
{
    struct CryptFS_Entry_ID current_directory_entry; // Current CryptFS_Entry
                                                     // Directory identifier (.)
    struct CryptFS_Entry entries[NB_ENTRIES_PER_BLOCK];
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

// -----------------------------------------------------------------------------
// CRYPTFS FILE SYSTEM
// -----------------------------------------------------------------------------
#define HEADER_BLOCK 0
#define KEYS_STORAGE_BLOCK (HEADER_BLOCK + 1)
#define FIRST_FAT_BLOCK (KEYS_STORAGE_BLOCK + NB_ENCRYPTION_KEYS)
#define ROOT_DIR_BLOCK (FIRST_FAT_BLOCK + 1)

struct CryptFS
{
    struct CryptFS_Header header; // BLOCK 0: Header
    struct CryptFS_KeySlot keys_storage[NB_ENCRYPTION_KEYS]; // BLOCK 1-64: Keys
    struct CryptFS_FAT first_fat; // BLOCK 65: First FAT
    struct CryptFS_Entry root_directory; // BLOCK 66: Root directory
} __attribute__((packed, aligned(CRYPTFS_BLOCK_SIZE_BYTES)));

#endif /* CRYPT_FS_H */
