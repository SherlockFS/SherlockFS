#include <stdio.h>

#include "fuse_mount.h"
#include "print.h"

void *cryptfs_init(struct fuse_conn_info *info)
{
    print_debug(".init() called\n");
    print_info("Mounting a SherlockFS filesystem instance...\n");
    print_debug("Using FUSE protocol %d.%d\n", info->proto_major,
                info->proto_minor);
    print_debug("Max readahead: %d\n", info->max_readahead);
    print_debug("Max write: %d\n", info->max_write);
    print_debug("Max background: %d\n", info->max_background);
    print_debug("Max foreground: %d\n", info->max_write);
    print_debug("FILESYSTEM WANT: Async read: %d\n", info->want & FUSE_CAP_ASYNC_READ);
    if (info->want & FUSE_CAP_ASYNC_READ)
    {
        info->want = info->want & ~FUSE_CAP_ASYNC_READ;
        print_warning("Asynchronous read asked by kernel but not currently supported by SherlockFS, this option will be ignored\n");
    }
    
    print_debug("FILESYSTEM WANT: Posix lock: %d\n", info->want & FUSE_CAP_POSIX_LOCKS);
    print_debug("FILESYSTEM WANT: File handle: %d\n", info->want & FUSE_CAP_FLOCK_LOCKS);
    print_debug("FILESYSTEM WANT: Auto inval: %d\n", info->want & FUSE_CAP_ATOMIC_O_TRUNC);
    print_debug("FILESYSTEM WANT: Big writes: %d\n", info->want & FUSE_CAP_BIG_WRITES);
    print_debug("FILESYSTEM WANT: Dont mask: %d\n", info->want & FUSE_CAP_DONT_MASK);
    print_debug("FILESYSTEM WANT: Splice write: %d\n", info->want & FUSE_CAP_SPLICE_WRITE);
    print_debug("FILESYSTEM WANT: Splice move: %d\n", info->want & FUSE_CAP_SPLICE_MOVE);
    print_debug("FILESYSTEM WANT: Splice read: %d\n", info->want & FUSE_CAP_SPLICE_READ);
    print_debug("FILESYSTEM WANT: Flock locks: %d\n", info->want & FUSE_CAP_FLOCK_LOCKS);
    print_debug("FILESYSTEM WANT: Has ioctl dir: %d\n", info->want & FUSE_CAP_IOCTL_DIR);

    info->async_read = 0; // Multi-threaded read not supported
    print_success("SherlockFS filesystem mounted successfully!\n");

    return NULL;
}
