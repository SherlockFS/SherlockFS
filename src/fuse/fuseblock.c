#include "fuseblock.h"

#include "block.h"

//TODO read multiple blocks at once
struct dirblock* get_dirblock(size_t block) {
    void *block = malloc(CRYPTFS_BLOCK_SIZE_BYTES);
    read_blocks(block, 1, )
}

struct statblock* get_statblock(size_t block);
struct datablock* get_datablock(size_t block);
