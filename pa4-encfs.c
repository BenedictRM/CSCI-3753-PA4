#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <limits.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>//For malloc
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>

struct xmp_state {
    char *rootdir;
};
#define XMP_DATA ((struct xmp_state *) fuse_get_context()->private_data)

#endif

static void xmp_fullpath(char fpath[PATH_MAX], const char *path) {
  strcpy(fpath, XMP_DATA->rootdir);
  strncat(fpath, path, sizeof(fpath)-strlen(fpath)-1); // ridiculously long paths will break here
  //Was getting retarded error so replaced strncat(fpath, path, PATH_MAX); 
}

static int xmp_getattr(const char *path, struct stat *statbuf) 
{
	int retstat = 0;
	char fpath[PATH_MAX];
	
	xmp_fullpath(fpath, path);
	
	retstat = lstat(fpath, statbuf);
	
	if (retstat == -1)
		return -errno;

	return retstat;
}	

static int xmp_access(const char *path, int mask)
{
	int res;
    char fpath[PATH_MAX];
    
    xmp_fullpath(fpath, path);
    
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	xmp_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;
    
    //void unused variables 
    (void) path;
	(void) offset;
	  
	dp = (DIR *) (uintptr_t) fi->fh;
	de = readdir(dp);
	
	if (de == 0)
		return -errno;
    
    // This will copy the entire directory into the buffer.  The loop exits
    // when either the system readdir() returns NULL, or filler()
    // returns something non-zero.  The first case just means I've
    // read the whole directory; the second means the buffer is full.
    
	do 
	{
         if (filler(buf, de->d_name, NULL, 0) != 0) {
              return -ENOMEM;
		 }
    } while ((de = readdir(dp)) != NULL);

    return retstat;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
    
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	   
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
    char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
    
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
    res = symlink(from, to);
    
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

    res = rename(from, to);
    
    if (res == -1){
       return -errno;
    }

  return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

    res = link(from, to);
    if (res == -1){
        return -errno;
   }

  return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
    char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);
    
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;
    char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);
    
	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;
	char fpath[PATH_MAX];
       
    xmp_fullpath(fpath, path);

	(void) fi;
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
        
    xmp_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    char fpath[PATH_MAX];
    int res;
 
    xmp_fullpath(fpath, path);
        
    (void) fi;

    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
    res = lsetxattr(fpath, name, value, size, flags);
	
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
	
	res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
	
	res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res;
	char fpath[PATH_MAX];
      
    xmp_fullpath(fpath, path);
	
	res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}

void *xmp_init(struct fuse_conn_info *conn) {
  (void) conn;
  return XMP_DATA;
}
/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int xmp_opendir(const char *path, struct fuse_file_info *fi) {
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    xmp_fullpath(fpath, path);

    dp = opendir(fpath);
    if (dp == NULL)
      retstat = -errno;

    fi->fh = (intptr_t) dp;

    return retstat;
}

/**
 * Release directory
 */
int xmp_releasedir(const char *path, struct fuse_file_info *fi) {
    int retstat = 0;
    (void) path;

    closedir((DIR *) (uintptr_t) fi->fh);

    return retstat;
}

void xmp_usage() {
    fprintf(stderr, "usage:  encfs [FUSE and mount options] passPhrase rootDir mountPoint\n");
    abort();
}

#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	//xmp_state for malloc, xmp_data to pull directory information
    umask(0);//Tells all files created to have no revoked priveleges   
    int fuse_stat;
    struct xmp_state *xmp_data;
    
    //From tutorial: Disallow root from mounting
     if ((getuid() == 0) || (geteuid() == 0)) {
	    fprintf(stderr, "Running ENCFS as root opens unnacceptable security holes\n");
        return 1;
     }
    
    //Tutorial command line parsing
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')){
	    xmp_usage();
	}

	xmp_data = malloc(sizeof(struct xmp_state));
    
    if (xmp_data == NULL) {
	    perror("main calloc");
	    abort();
    }
    
    
    //Malloc the data pointer
    //xmp_data = malloc(sizeof(struct xmp_state));
    
    // Pull the rootdir out of the argument list and save it in the
    // internal data, realpath is a c command sets the root directory for you
    xmp_data->rootdir = realpath(argv[argc-2], NULL);
    
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    
	//Create the mirrored directory with xmp_data
	// turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &xmp_oper, xmp_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
			
	return fuse_stat;
}
