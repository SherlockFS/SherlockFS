#include "fuse_mount.h"
#include "print.h"

int cryptfs_releasedir(const char *path, struct fuse_file_info *file)
{
    print_debug("releasedir(path=%s, file=%p)\n", path, file);
    return -1;
}

int cryptfs_create(const char *path, mode_t mode, struct fuse_file_info *file)
{
    print_debug("create(path=%s, mode=%d, file=%p)\n", path, mode, file);
    return -1;
}

int cryptfs_ftruncate(const char *path, off_t offset,
                      struct fuse_file_info *file)
{
    print_debug("ftruncate(path=%s, offset=%ld, file=%p)\n", path, offset,
                file);
    return -1;
}

int cryptfs_access(const char *path, int mode)
{
    print_debug("access(path=%s, mode=%d)\n", path, mode);
    return -1;
}

int cryptfs_flush(const char *path, struct fuse_file_info *file)
{
    print_debug("flush(path=%s, file=%p)\n", path, file);
    return -1;
}

int cryptfs_fsync(const char *path, int datasync, struct fuse_file_info *file)
{
    print_debug("fsync(path=%s, datasync=%d, file=%p)\n", path, datasync, file);
    return -1;
}

int cryptfs_fsyncdir(const char *path, int datasync,
                     struct fuse_file_info *file)
{
    print_debug("fsyncdir(path=%s, datasync=%d, file=%p)\n", path, datasync,
                file);
    return -1;
}

int cryptfs_mkdir(const char *path, mode_t mode)
{
    print_debug("mkdir(path=%s, mode=%d)\n", path, mode);
    return -1;
}

int cryptfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    print_debug("mknod(path=%s, mode=%d, rdev=%d)\n", path, mode, rdev);
    return -1;
}

int cryptfs_readlink(const char *path, char *buf, size_t size)
{
    print_debug("readlink(path=%s, buf=%p, size=%ld)\n", path, buf, size);
    return -1;
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

int cryptfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset,
                      struct fuse_file_info *file)
{
    print_debug("write_buf(path=%s, buf=%p, offset=%ld, file=%p)\n", path, buf,
                offset, file);
    return -1;
}

int cryptfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size,
                     off_t offset, struct fuse_file_info *file)
{
    print_debug("read_buf(path=%s, bufp=%p, size=%ld, offset=%ld, file=%p)\n",
                path, bufp, size, offset, file);
    return -1;
}

int cryptfs_opendir(const char *path, struct fuse_file_info *file)
{
    print_debug("opendir(path=%s, file=%p)\n", path, file);
    return -1;
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
    return -1;
}

int cryptfs_unlink(const char *path)
{
    print_debug("unlink(path=%s)\n", path);
    return -1;
}

int cryptfs_symlink(const char *target, const char *link)
{
    print_debug("symlink(target=%s, link=%s)\n", target, link);
    return -1;
}

int cryptfs_link(const char *oldpath, const char *newpath)
{
    print_debug("link(oldpath=%s, newpath=%s)\n", oldpath, newpath);
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
    return -1;
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
    return -1;
}

int cryptfs_listxattr(const char *path, char *list, size_t size)
{
    print_debug("listxattr(path=%s, list=%s, size=%ld)\n", path, list, size);
    return -1;
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
    return -1;
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
    return -1;
}
