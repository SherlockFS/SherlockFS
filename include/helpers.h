//
// Created by chalu on 4/21/2024.
//

#ifndef SHERLOCKFS_HELPERS_H
#define SHERLOCKFS_HELPERS_H

#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS  64
#include "cryptfs.h"
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

int search_entry(const char *path, struct CryptFS_Entry entry);
int __search_entry_in_directory(unsigned char* aes_key, struct CryptFS_Entry_ID* entry_id);

#endif //SHERLOCKFS_HELPERS_H
