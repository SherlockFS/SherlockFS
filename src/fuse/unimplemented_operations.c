#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "entries.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "print.h"

#define MIN(x, y) ((x) > (y) ? (y) : (x))

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
int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset,
                      struct fuse_file_info *file)
{
    print_debug("write_buf(path=%s, buf=%p, offset=%ld, file=%p)\n", path, buf,
                offset, file);

    // Get entry ID from file
    struct fs_file_info *ffi = (struct fs_file_info *)file->fh;
    struct CryptFS_Entry_ID entry_id = ffi->uid;

    (void)ffi;
    (void)entry_id;

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
}

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
