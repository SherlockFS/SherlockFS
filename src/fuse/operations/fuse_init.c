#include <stdio.h>

#include "fuse_mount.h"

void *cryptfs_init(struct fuse_conn_info *info)
{
    printf("Using FUSE protocol %d.%d\n", info->proto_major, info->proto_minor);
    return NULL;
}
