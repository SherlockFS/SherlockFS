#include "cryptfs.h"
#include "print.h"

#define STATIC_ASSERT(X)                                                       \
    ({                                                                         \
        extern int __attribute__((                                             \
            error("assertion failure at compilation: '" #X "' not true")))     \
        compile_time_check();                                                  \
        ((X) ? 0 : compile_time_check()), 0;                                   \
    })

__attribute__((unused)) static void my_constraints()
{
    STATIC_ASSERT(sizeof(struct CryptFS_KeySlot) <= CRYPTFS_BLOCK_SIZE_BYTES);
    STATIC_ASSERT(sizeof(struct CryptFS_Header) <= CRYPTFS_BLOCK_SIZE_BYTES);
    STATIC_ASSERT(sizeof(struct CryptFS_Entry) <= CRYPTFS_BLOCK_SIZE_BYTES);
}
