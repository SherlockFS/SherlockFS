#ifndef FUSE_BLOCK_H
#define FUSE_BLOCK_H

#include <unistd.h>

enum block_type
{
    DATA = 0,
    STAT = 1,
    DIR = 2
};

/**
 * @brief Block type is DATA.
 */
struct datablock
{
    enum block_type type;
    size_t next_block;
    size_t sz;
    char data[];
};

struct fusestat
{
    // TODO stat
    size_t data_block;
    size_t size;
};

/**
 * @brief Block type is STAT.
 * Contains everything relevant about nodes, links, files etc...
 */
struct statblock
{
    enum block_type type;
    size_t elems;
    struct fusestat stats[];
};

/**
 * @brief This struct should never exceed size 16 + 256 = 272 bytes.
 * Ends with a null character.
 */
struct nodeptr
{
    size_t stat_block;
    size_t id;
    char name[];
};

/**
 * @brief Block type is DIR.
 * The data in the filesystem blocks that contain
 * everything a saved directory contains.
 * To access the next block use the offset
 * indicated by next_block or ignore if it is 0.
 * Each elements of elems ends with a null character.
 * First block of every filesystem is the root's dirblock.
 */
struct dirblock
{
    enum block_type type;
    unsigned int nodes;
    size_t next_block;
    struct nodeptr elems[];
};

struct dirblock *get_dirblock(size_t block);
struct statblock *get_statblock(size_t block);
struct datablock *get_datablock(size_t block);

int merge_blocks(size_t starting);

void swap_blocks(size_t block1, size_t block2);

/**
 * @brief It is the responsibility of the user to free
 * the returned pointer (not the contained strings though).
 *
 * @param block The first block
 * @return char** A NULL terminated list of names that the user has to free
 */
char **read_dirblock(size_t block);

/**
 * @brief It is the responsibility of the user to free
 * the returned pointer (not the contained strings though).
 *
 * @return char** A NULL terminated list of names that the user has to free
 */
char **read_rootdir();

size_t get_dirblock_by_path(const char *path);

#endif /* FUSE_BLOCK_H */