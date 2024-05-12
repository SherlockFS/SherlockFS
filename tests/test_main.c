#include <assert.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "adduser.h"
#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "deluser.h"
#include "entries.h"
#include "fat.h"
#include "format.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

// Create mock filler function
int filler(void *buf, const char *name, const struct stat *stbuf, off_t off)
{
    printf("Buf: %p\n", buf);
    printf("Name: %s\n", name);
    printf("stbuf: %p\n", stbuf);
    printf("Offset: %ld\n", off);

    return 0;
}

int main(void)
{
    // set_device_path("/home/nathan/epita/SherlockFS/build/test.shlkfs");

    // fpi_register_master_key_from_path(
    //     "/home/nathan/epita/SherlockFS/build/test.shlkfs",
    //     "/home/nathan/.sherlockfs/private.pem");

    // struct CryptFS_Entry_ID eid = { .directory_block = ROOT_DIR_BLOCK,
    //                                 .directory_index = 5 };

    // // Get entry by id
    // struct CryptFS_Entry *entry = get_entry_from_id(fpi_get_master_key(),
    // eid);

    // // Print entry fields
    // print_info("Entry used: %d\n", entry->used);
    // print_info("Entry name: %s\n", entry->name);
    // print_info("Entry type: %d\n", entry->type);
    // print_info("Entry size: %d\n", entry->size);
    // print_info("Entry block: %d\n", entry->start_block);

    // // readdir variables
    // char buf[4096];
    // struct fuse_file_info fi = { 0 };

    // struct CryptFS_Entry_ID directory_entry_id = { .directory_block =
    //                                                    ROOT_ENTRY_BLOCK,
    //                                                .directory_index = 0 };
    // fi.fh = (uint64_t)&directory_entry_id;
    // off_t offset = 0;

    // cryptfs_readdir("/", buf, filler, offset, &fi);

    // struct stat stbuf = { 0 };
    // cryptfs_getattr("/test.txt", &stbuf);

    // // free(eid);
    // free(entry);

    system("dd if=/dev/zero "
           "of=get_entry_by_path.two_file_in_one_dir.test.shlkfs "
           "bs=4096 count=100");

    set_device_path("get_entry_by_path.two_file_in_one_dir.test.shlkfs");

    format_fs("get_entry_by_path.two_file_in_one_dir.test.shlkfs",
              "get_entry_by_path.two_file_in_one_dir.public.pem",
              "get_entry_by_path.two_file_in_one_dir.private.pem", "label",
              NULL, NULL);

    fpi_register_master_key_from_path(
        "get_entry_by_path.two_file_in_one_dir.test.shlkfs",
        "get_entry_by_path.two_file_in_one_dir.private.pem");

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), "/");

    assert(entry_id->directory_block == ROOT_ENTRY_BLOCK);
    assert(entry_id->directory_index == 0);

    entry_create_directory(fpi_get_master_key(), *entry_id, "test_directory");

    struct CryptFS_Entry_ID *entry_id_test_directory =
        get_entry_by_path(fpi_get_master_key(), "/test_directory");

    assert(entry_id_test_directory != (void *)ENTRY_NO_SUCH);
    assert(entry_id_test_directory->directory_block == ROOT_DIR_BLOCK);
    assert(entry_id_test_directory->directory_index == 0);

    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file");
    entry_create_empty_file(fpi_get_master_key(), *entry_id_test_directory,
                            "test_file2");

    // Get entry from ID
    struct CryptFS_Entry *test_directory =
        get_entry_from_id(fpi_get_master_key(), *entry_id_test_directory);
    struct CryptFS_Entry_ID *entry_id_test_file =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file");

    assert(entry_id_test_file != (void *)ENTRY_NO_SUCH);
    assert(entry_id_test_file->directory_block == test_directory->start_block);
    assert(entry_id_test_file->directory_index == 0);

    struct CryptFS_Entry_ID *entry_id_test_file2 =
        get_entry_by_path(fpi_get_master_key(), "/test_directory/test_file2");

    assert(entry_id_test_file2 != (void *)ENTRY_NO_SUCH);

    return 0;
}
