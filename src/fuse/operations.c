#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"
#include "xalloc.h"

#define MIN(x, y) ((x) > (y) ? (y) : (x))

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
    print_debug("FILESYSTEM WANT: Async read: %d\n",
                info->want & FUSE_CAP_ASYNC_READ);
    if (info->want & FUSE_CAP_ASYNC_READ)
    {
        info->want = info->want & ~FUSE_CAP_ASYNC_READ;
        print_warning("Asynchronous read asked by kernel but not currently "
                      "supported by SherlockFS, this option will be ignored\n");
    }

    print_debug("FILESYSTEM WANT: Posix lock: %d\n",
                info->want & FUSE_CAP_POSIX_LOCKS);
    print_debug("FILESYSTEM WANT: File handle: %d\n",
                info->want & FUSE_CAP_FLOCK_LOCKS);
    print_debug("FILESYSTEM WANT: Auto inval: %d\n",
                info->want & FUSE_CAP_ATOMIC_O_TRUNC);
    print_debug("FILESYSTEM WANT: Big writes: %d\n",
                info->want & FUSE_CAP_BIG_WRITES);
    print_debug("FILESYSTEM WANT: Dont mask: %d\n",
                info->want & FUSE_CAP_DONT_MASK);
    print_debug("FILESYSTEM WANT: Splice write: %d\n",
                info->want & FUSE_CAP_SPLICE_WRITE);
    print_debug("FILESYSTEM WANT: Splice move: %d\n",
                info->want & FUSE_CAP_SPLICE_MOVE);
    print_debug("FILESYSTEM WANT: Splice read: %d\n",
                info->want & FUSE_CAP_SPLICE_READ);
    print_debug("FILESYSTEM WANT: Flock locks: %d\n",
                info->want & FUSE_CAP_FLOCK_LOCKS);
    print_debug("FILESYSTEM WANT: Has ioctl dir: %d\n",
                info->want & FUSE_CAP_IOCTL_DIR);

    info->async_read = 0; // Multi-threaded read not supported
    print_success("SherlockFS filesystem mounted successfully!\n");

    return NULL;
}

int cryptfs_getattr(const char *path, struct stat *stbuf)
{
    print_debug("getattr(path=%s, stbuf=%p)\n", path, stbuf);
    // if (stbuf == NULL)
    //     return -EINVAL;

    // Init the buffer
    memset(stbuf, 0, sizeof(struct stat));

    // Allocate struct for reading directory_block
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    switch ((uint64_t)entry_id)
    {
    case BLOCK_ERROR:
        print_debug("getattr(%s, %p) -> -EIO\n", path, stbuf);
        return -EIO;
    case ENTRY_NO_SUCH:
        print_debug("getattr(%s, %p) -> -ENOENT\n", path, stbuf);
        return -ENOENT;
    default:
        break;
    }

    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);
    fpi_clear_decoded_key();

    free(entry_id);

    if (entry->type == ENTRY_TYPE_DIRECTORY)
        stbuf->st_mode = __S_IFDIR | entry->mode;

    else if (entry->type == ENTRY_TYPE_FILE
             || entry->type == ENTRY_TYPE_HARDLINK)
        stbuf->st_mode = __S_IFREG | entry->mode;

    else if (entry->type == ENTRY_TYPE_SYMLINK)
        stbuf->st_mode = __S_IFLNK | entry->mode;
    else
    {
        free(entry);
        print_debug("getattr(%s, %p) -> -ENOENT\n", path, stbuf);
        return -ENOENT;
    }

    stbuf->st_nlink = 1; // TODO: Number of hardlinks
    stbuf->st_uid = entry->uid;
    stbuf->st_gid = entry->gid;
    stbuf->st_atime = entry->atime;
    stbuf->st_mtime = entry->mtime;
    stbuf->st_ctime = entry->ctime;
    stbuf->st_size = entry->size;
    free(entry);

    print_debug("getattr(%s, %p) -> 0\n", path, stbuf);
    return 0;
}

int cryptfs_open(const char *path, struct fuse_file_info *file)
{
    print_debug("open(%s, %p)\n", path, file);

    // FD management / allocation
    struct fs_file_info *ffi = xcalloc(1, sizeof(struct fs_file_info));

    // set default value
    ffi->is_readable_mode = false;
    ffi->is_writable_mode = false;

    // open() flags management
    if ((file->flags & O_ACCMODE) == O_RDONLY) // Read only
        ffi->is_readable_mode = true;
    else if ((file->flags & O_ACCMODE) == O_WRONLY) // Write only
        ffi->is_writable_mode = true;
    else // ((file->flags & O_ACCMODE) == O_RDWR) // Read and write
    {
        ffi->is_readable_mode = true;
        ffi->is_writable_mode = true;
    }

    // File open / creation management
    // Open the file
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);
    switch ((uint64_t)entry_id)
    {
    case BLOCK_ERROR:
        print_error("open(%s, %p) -> -EIO\n", path, file);
        return -EIO;
    case ENTRY_NO_SUCH:
        print_error("open(%s, %p) -> -ENOENT\n", path, file);
        return -ENOENT;
    default:
        break;
    }
   

    ffi->uid = *entry_id;
    ffi->seek_offset = 0;         

    file->fh = (uint64_t)ffi; // File handle is the file information structure
    fpi_clear_decoded_key();
    free(entry_id);

    print_debug("open(%s, %p) -> 0\n", path, file);
    return 0;
}

int cryptfs_read(const char *path, char *buf, size_t sz, off_t offset,
                 struct fuse_file_info *file)
{
    print_debug("read(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p)\n", path,
                buf, sz, offset, file);

    // Number of byte actually read
    ssize_t byte_read;

    // Number of byte to read
    size_t byte_to_read;

    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    // Test the permission
    if (ffi->is_readable_mode == false) {
        print_error("read(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> -EACCES\n", path,
                buf, sz, offset, file);
        return -EACCES;
    }
        
    
    struct CryptFS_Entry *entry = get_entry_from_id(fpi_get_master_key(), entry_id);

    // Get the actual size of the file
    byte_to_read = entry->size;
    byte_to_read = byte_to_read < sz ? byte_to_read: sz;

    // Read data
    byte_read =
        entry_read_raw_data(fpi_get_master_key(), entry_id, offset + ffi->seek_offset, buf, byte_to_read);
    fpi_clear_decoded_key();

    if (byte_read == BLOCK_ERROR)
    {
        print_error("read(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> -EIO\n", path,
                buf, sz, offset, file);
        return -EIO;
    }
        
    print_debug("read(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> %u\n", path,
                buf, sz, offset, file, byte_to_read);
    return byte_to_read;
}

int cryptfs_write(const char *path, const char *buf, size_t sz, off_t offset,
                  struct fuse_file_info *file)
{
    print_debug("write(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p)\n", path,
                buf, sz, offset, file);
    ssize_t byte_write;
   
    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;
    
    if (ffi->is_writable_mode == false)
    {
        print_error("write(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> -EACCESS\n", path,
                buf, sz, offset, file);
        return -EACCES;
    }
    
    // Write data
    byte_write = entry_write_buffer_from(fpi_get_master_key(), entry_id, offset, buf, sz);
    fpi_clear_decoded_key();


    if (byte_write == BLOCK_ERROR)
    {
        print_error("write(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> -EIO\n", path,
                buf, sz, offset, file);
        return -EIO;
    }
        

    print_debug("write(path=%s, buf=%p, sz=%lu, offset=%ld, file=%p) -> %u\n", path,
                buf, sz, offset, file, sz);
    return sz;
}

/*
off_t crypfs_lseek(const char *path, off_t off, int whence, struct fuse_file_info *file)
{
    print_debug("lseek(path=%s, off=%p, whence=%p, file=%ld)\n",
                path, off, whence, file);
    
    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    switch (whence)
    {
    case SEEK_SET:
        ffi->seek_offset = off;
        break;
    case SEEK_CUR:
        ffi->seek_offset += off;
        break;
    case SEEK_END:
        struct CryptFS_Entry *entry = get_entry_from_id(fpi_get_master_key(), entry_id);
        fpi_clear_decoded_key();
        ffi->seek_offset = entry->size + off;
        break;
    default:
        print_error("lseek(path=%s, off=%p, whence=%p, file=%ld) -> EINVAL\n",
                path, off, whence, file);
        return -EINVAL;
    }

    print_debug("lseek(path=%s, off=%p, whence=%p, file=%ld) -> %u\n",
                path, off, whence, file, ffi->seek_offset);
    return ffi->seek_offset;
}
*/

int cryptfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                    off_t offset, struct fuse_file_info *fi)
{
    print_debug("readdir(path=%s, buf=%p, filler=%p, offset=%ld, fi=%p)\n",
                path, buf, filler, offset, fi);

    // Get the entry ID of the directory
    struct CryptFS_Entry_ID *directory_entry_id =
        (struct CryptFS_Entry_ID *)fi->fh;

    // Get entry from the entry ID
    struct CryptFS_Entry *directory_entry =
        get_entry_from_id(fpi_get_master_key(), *directory_entry_id);

    filler(buf, ".", NULL, 0); // Current Directory
    filler(buf, "..", NULL, 0); // Parent Directory
    for (uint64_t i = offset; i < directory_entry->size; i++)
    {
        // goto_used_entry_in_directory
        struct CryptFS_Entry_ID *entry_id = goto_used_entry_in_directory(
            fpi_get_master_key(), *directory_entry_id, i);

        // Get entry from the entry ID
        struct CryptFS_Entry *entry =
            get_entry_from_id(fpi_get_master_key(), *entry_id);

        struct stat stbuf;
        stbuf.st_mode = entry->mode;
        stbuf.st_nlink = 1;
        stbuf.st_uid = entry->uid;
        stbuf.st_gid = entry->gid;
        stbuf.st_size = entry->size;
        stbuf.st_atime = entry->atime;
        stbuf.st_mtime = entry->mtime;
        stbuf.st_ctime = entry->ctime;

        filler(buf, entry->name, &stbuf, 0);

        free(entry_id);
        free(entry);
    }

    free(directory_entry);

    print_debug("readdir(%s, %p, %p, %ld, %p) -> 0\n", path, buf, filler,
                offset, fi);
    return 0;
}

int cryptfs_release(const char *path, struct fuse_file_info *file)
{
    print_debug("release(path=%s, file=%p)\n", path, file);

    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    if (ffi)
        free(ffi);

    return 0;
}

int cryptfs_releasedir(const char *path, struct fuse_file_info *file)
{
    print_debug("releasedir(path=%s, file=%p)\n", path, file);

    free((void *)file->fh);
    return 0;
}

int cryptfs_create(const char *path, mode_t mode, struct fuse_file_info *file)
{
    print_debug("create(path=%s, mode=%d, file=%p)\n", path, mode, file);

    struct CryptFS_Entry_ID *entry_id =
        create_file_by_path(fpi_get_master_key(), path);

    switch ((uint64_t)entry_id)
    {
    case ENTRY_EXISTS:
        break; // Can open the file
    case ENTRY_NO_SUCH:
        print_debug("create(path=%s, mode=%d, file=%p) = %d\n", path, mode,
                    file, -ENOENT);
        return -ENOENT;
    case BLOCK_ERROR:
        print_debug("create(path=%s, mode=%d, file=%p) = %d\n", path, mode,
                    file, -EIO);
        return -EIO;
    default:
        free(entry_id);
        break;
    }

    return cryptfs_open(path, file);
}
int cryptfs_ftruncate(const char *path, off_t offset,
                      struct fuse_file_info *file)
{
    print_debug("ftruncate(path=%s, offset=%ld, file=%p)\n", path, offset,
                file);

    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    switch (entry_truncate(fpi_get_master_key(), entry_id, offset))
    {
    case BLOCK_ERROR:
        return -EIO;
        break;
    default:
        break;
    }
    print_debug("ftruncate(path=%s, offset=%ld, file=%p) = %d\n", path, offset,
                file, 0);
    return 0;
}

int cryptfs_access(const char *path, int mode)
{
    print_debug("access(path=%s, mode=%d)\n", path, mode);

    // Get entry ID from path
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    switch ((uint64_t)entry_id)
    {
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }

    // Only check if the file exists
    if (mode != 0)
    {
        // Get entry from ID
        struct CryptFS_Entry *entry =
            get_entry_from_id(fpi_get_master_key(), *entry_id);

        if (mode & R_OK)
        {
            // Get current user ID et group ID
            uid_t uid = getuid();
            gid_t gid = getgid();

            // Check if the user has read permission
            if (entry->uid == uid && (entry->mode & S_IRUSR) == 0)
                return -EACCES;
            if (entry->gid == gid && (entry->mode & S_IRGRP) == 0)
                return -EACCES;
            if ((entry->mode & S_IROTH) == 0)
                return -EACCES;
        }

        if (mode & W_OK)
        {
            // Get current user ID et group ID
            uid_t uid = getuid();
            gid_t gid = getgid();

            // Check if the user has write permission
            if (entry->uid == uid && (entry->mode & S_IWUSR) == 0)
                return -EACCES;
            if (entry->gid == gid && (entry->mode & S_IWGRP) == 0)
                return -EACCES;
            if ((entry->mode & S_IWOTH) == 0)
                return -EACCES;
        }

        if (mode & X_OK)
        {
            // Get current user ID et group ID
            uid_t uid = getuid();
            gid_t gid = getgid();

            // Check if the user has execute permission
            if (entry->uid == uid && (entry->mode & S_IXUSR) == 0)
                return -EACCES;
            if (entry->gid == gid && (entry->mode & S_IXGRP) == 0)
                return -EACCES;
            if ((entry->mode & S_IXOTH) == 0)
                return -EACCES;
        }
    }

    print_debug("access(path=%s, mode=%d) = %d\n", path, mode, 0);
    return 0;
}

int cryptfs_flush(const char *path, struct fuse_file_info *file)
{
    print_debug("flush(path=%s, file=%p)\n", path, file);

    print_debug("We do no cache anything, so we do nothing here\n");
    return 0;
}

int cryptfs_fsync(const char *path, int datasync, struct fuse_file_info *file)
{
    print_debug("fsync(path=%s, datasync=%d, file=%p)\n", path, datasync, file);

    print_debug("We do no cache anything, so we do nothing here\n");
    return 0;
}

int cryptfs_fsyncdir(const char *path, int datasync,
                     struct fuse_file_info *file)
{
    print_debug("fsyncdir(path=%s, datasync=%d, file=%p)\n", path, datasync,
                file);

    print_debug("We do no cache anything, so we do nothing here\n");
    return 0;
}

int cryptfs_mkdir(const char *path, mode_t mode)
{
    print_debug("mkdir(path=%s, mode=%d)\n", path, mode);

    switch ((uint64_t)create_directory_by_path(fpi_get_master_key(), path))
    {
    case ENTRY_EXISTS:
        return -EEXIST;
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }

    return 0;
}

int cryptfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    print_debug("mknod(path=%s, mode=%d, rdev=%d)\n", path, mode, rdev);

    struct CryptFS_Entry_ID *entry_id = NULL;

    if (mode & S_IFREG)
        entry_id = create_file_by_path(fpi_get_master_key(), path);
    else if (mode & S_IFDIR)
        entry_id = create_directory_by_path(fpi_get_master_key(), path);
    else if (mode & S_IFLNK)
        entry_id = create_symlink_by_path(fpi_get_master_key(), "", path);
    else
        return -EINVAL;

    switch ((uint64_t)entry_id)
    {
    case ENTRY_EXISTS:
        return -EEXIST;
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }

    return 0;
}

int cryptfs_readlink(const char *path, char *buf, size_t size)
{
    int err = 0;

    print_debug("readlink(path=%s, buf=%p, size=%ld)\n", path, buf, size);

    // Get entry ID from path
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    switch ((uint64_t)entry_id)
    {
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }

    // Get entry from ID
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    if (entry->type != ENTRY_TYPE_SYMLINK)
    {
        err = -EINVAL;
        goto err;
    }

    if (entry_read_raw_data(fpi_get_master_key(), *entry_id, 0, buf,
                            MIN(size, entry->size))
        == BLOCK_ERROR)
    {
        err = -EIO;
        goto err;
    }
err:
    free(entry_id);
    free(entry);
    return err;
}

int cryptfs_rename(const char *oldpath, const char *newpath)
{
    print_debug("rename(oldpath=%s, newpath=%s)\n", oldpath, newpath);
    return -1;
}

int cryptfs_fallocate(const char *path, int mode, off_t offset, off_t length,
                      struct fuse_file_info *file)
{
    print_debug("fallocate(path=%s, mode=%d, offset=%ld, length=%ld, "
                "file=%p)\n",
                path, mode, offset, length, file);
    return -1;
}

// TODO: Implement
/*
int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset,
                      struct fuse_file_info *file)
{
    print_debug("write_buf(path=%s, buf=%p, offset=%ld, file=%p)\n", path, buf,
                offset, file);

    ssize_t byte_write;

    // Get entry ID from file
    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    print_debug("Call to write buffer from\n");
    if (ffi->is_writable_mode == false)
        return -1;

    print_debug("Call to write buffer from\n");
    byte_write = entry_write_buffer_from(fpi_get_master_key(), entry_id, offset, buf, sz);
    fpi_clear_decoded_key();
    if (byte_write == BLOCK_ERROR)
        return -EIO;
    print_debug("write(number byte write: %u)\n", byte_write);
    return byte_write;
}

    return 0;
}

// TODO: Implement
int cryptfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size,
                     off_t offset, struct fuse_file_info *file)
{
    print_debug("read_buf(path=%s, bufp=%p, size=%ld, offset=%ld, file=%p)\n",
                path, bufp, size, offset, file);

    // Get entry ID from file
    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    return entry_read_raw_data(fpi_get_master_key(), entry_id, offset,
                               bufp[0]->buf->mem, size);
}*/

int cryptfs_opendir(const char *path, struct fuse_file_info *file)
{
    print_debug("opendir(path=%s, file=%p)\n", path, file);

    // Get directory from path
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    // Check if the directory exists
    if (entry_id == (void *)ENTRY_NO_SUCH)
        return -ENOENT;
    if (entry_id == (void *)BLOCK_ERROR)
        return -EIO;

    // Get entry from ID
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    // Check if the entry is a directory
    if (entry->type != ENTRY_TYPE_DIRECTORY)
        return -ENOTDIR;

    // ! Not ffi but entry_id for a directory
    file->fh = (uint64_t)entry_id;

    // Free memory
    free(entry);

    return 0;
}

void cryptfs_destroy(void *userdata)
{
    print_debug("destroy(userdata=%p)\n", userdata);
}

int cryptfs_statfs(const char *path, struct statvfs *stats)
{
    print_debug("statfs(path=%s, stats=%p)\n", path, stats);
    return -1;
}

int cryptfs_rmdir(const char *path)
{
    print_debug("rmdir(path=%s)\n", path);

    // Get entry ID from path
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    // Check if the directory exists
    if (entry_id == (void *)ENTRY_NO_SUCH)
        return -ENOENT;

    // Check if the entry is a directory
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    if (entry->type != ENTRY_TYPE_DIRECTORY)
        return -ENOTDIR;

    switch (delete_entry_by_path(fpi_get_master_key(), path))
    {
    case 0:
        return 0;
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }
    return -1;
}

int cryptfs_unlink(const char *path)
{
    print_debug("unlink(path=%s)\n", path);

    // Get entry ID from path
    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    // Check if the directory exists
    if (entry_id == (void *)ENTRY_NO_SUCH)
        return -ENOENT;

    // Check if the entry is a directory
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    if (entry->type == ENTRY_TYPE_DIRECTORY)
        return -EISDIR;

    switch (delete_entry_by_path(fpi_get_master_key(), path))
    {
    case 0:
        return 0;
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case BLOCK_ERROR:
        return -EIO;
    default:
        break;
    }
    return -1;
}

int cryptfs_symlink(const char *target, const char *path)
{
    print_debug("symlink(target=%s, path=%s)\n", target, path);

    switch (
        (uint64_t)create_symlink_by_path(fpi_get_master_key(), path, target))
    {
    case ENTRY_NO_SUCH:
        print_debug("symlink(%s, %s) = %d\n", target, path, -ENOENT);
        return -ENOENT;
    case ENTRY_EXISTS:
        print_debug("symlink(%s, %s) = %d\n", target, path, -EEXIST);
        return -EEXIST;
    case BLOCK_ERROR:
        print_debug("symlink(%s, %s) = %d\n", target, path, -EIO);
        return -EIO;
    default:
        break;
    }
    return 0;
}

int cryptfs_link(const char *oldpath, const char *newpath)
{
    print_debug("link(oldpath=%s, newpath=%s)\n", oldpath, newpath);

    switch ((uint64_t)create_hardlink_by_path(fpi_get_master_key(), newpath,
                                              oldpath))
    {
    case ENTRY_NO_SUCH:
        return -ENOENT;
    case ENTRY_EXISTS:
        return -EEXIST;
    case BLOCK_ERROR:
        return -EIO;
    default:
        return 0;
    }
    return -1;
}

int cryptfs_chmod(const char *path, mode_t mode)
{
    print_debug("chmod(path=%s, mode=%d)\n", path, mode);
    return -1;
}

int cryptfs_chown(const char *path, uid_t uid, gid_t gid)
{
    print_debug("chown(path=%s, uid=%d, gid=%d)\n", path, uid, gid);
    return -1;
}

int cryptfs_truncate(const char *path, off_t offset)
{
    print_debug("truncate(path=%s, offset=%ld)\n", path, offset);

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    switch (entry_truncate(fpi_get_master_key(), *entry_id, offset))
    {
    case BLOCK_ERROR:
        return -EIO;
        break;
    default:
        break;
    }
    return 0;
}

int cryptfs_setxattr(const char *path, const char *name, const char *value,
                     size_t size, int flags)
{
    print_debug("setxattr(path=%s, name=%s, value=%s, size=%ld, flags=%d)\n",
                path, name, value, size, flags);
    return -1;
}

int cryptfs_getxattr(const char *path, const char *name, char *value,
                     size_t size)
{
    print_debug("getxattr(path=%s, name=%s, value=%s, size=%ld)\n", path, name,
                value, size);
    return 0;
}

int cryptfs_listxattr(const char *path, char *list, size_t size)
{
    print_debug("listxattr(path=%s, list=%s, size=%ld)\n", path, list, size);
    return 0;
}

int cryptfs_removexattr(const char *path, const char *name)
{
    print_debug("removexattr(path=%s, name=%s)\n", path, name);
    return -1;
}

int cryptfs_lock(const char *path, struct fuse_file_info *file, int cmd,
                 struct flock *lock)
{
    print_debug("lock(path=%s, file=%p, cmd=%d, lock=%p)\n", path, file, cmd,
                lock);
    return -1;
}

int cryptfs_utimens(const char *path, const struct timespec tv[2])
{
    print_debug("utimens(path=%s, tv=%p)\n", path, tv);

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    // Get entry from ID
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    entry->atime = tv[0].tv_sec;
    entry->mtime = tv[1].tv_sec;

    if (write_entry_from_id(fpi_get_master_key(), *entry_id, entry)
        == BLOCK_ERROR)
        return -EIO;

    return 0;
}

int cryptfs_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
    print_debug("bmap(path=%s, blocksize=%ld, idx=%p)\n", path, blocksize, idx);
    return -1;
}

int cryptfs_ioctl(const char *path, int cmd, void *arg,
                  struct fuse_file_info *fi, unsigned int flags, void *data)
{
    print_debug("ioctl(path=%s, cmd=%d, arg=%p, fi=%p, flags=%d, data=%p)\n",
                path, cmd, arg, fi, flags, data);
    return -1;
}

int cryptfs_poll(const char *path, struct fuse_file_info *fi,
                 struct fuse_pollhandle *ph, unsigned *reventsp)
{
    print_debug("poll(path=%s, fi=%p, ph=%p, reventsp=%p)\n", path, fi, ph,
                reventsp);
    return -1;
}

int cryptfs_flock(const char *path, struct fuse_file_info *fi, int op)
{
    print_debug("flock(path=%s, fi=%p, op=%d)\n", path, fi, op);
    return -1;
}

int cryptfs_utime(const char *path, struct utimbuf *buf)
{
    print_debug("utime(path=%s, buf=%p)\n", path, buf);

    struct CryptFS_Entry_ID *entry_id =
        get_entry_by_path(fpi_get_master_key(), path);

    // Get entry from ID
    struct CryptFS_Entry *entry =
        get_entry_from_id(fpi_get_master_key(), *entry_id);

    entry->atime = buf->actime;
    entry->mtime = buf->modtime;

    if (write_entry_from_id(fpi_get_master_key(), *entry_id, entry)
        == BLOCK_ERROR)
        return -EIO;

    return 0;
}
