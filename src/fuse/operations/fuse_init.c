#include <stdio.h>

#include "fuse_mount.h"
#include "print.h"

void *cryptfs_init(struct fuse_conn_info *info)
{
    print_info("Mounting a SherlockFS filesystem instance...\n");
    print_debug("Using FUSE protocol %d.%d\n", info->proto_major,
                info->proto_minor);
    print_success("SherlockFS filesystem mounted successfully!\n");

    return NULL;
}
