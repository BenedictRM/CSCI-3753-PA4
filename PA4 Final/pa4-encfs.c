/*
 * File: pa4-encfs.c
 * Author: Russell Mehring with program start based on Andy Sayler's work
 * and assistance on xmp_read and xmp_write functions from Miles Rufat-Latre
 * Project: CSCI 3753 Programming Assignment 4
 * Create Date: 04/16/2014
 * Modify Date: 04/24/2014
 * Description:
 * 	This file contains an encrypting solution to the assignment
 *  
 */

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

//Set the action call possibilities for do_crypt
#define DONOTHING -1
#define DECRYPT 0
#define ENCRYPT 1

//Definitions of extended attribute name and values
#define XATTR_ENCRYPTED_FLAG "user.pa4-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 700
#endif

#include "aes-crypt.h"//For encryption support
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <limits.h>//FOR PATH_MAX
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>//For malloc
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>

#endif

struct bb_state {
    char *rootdir;
    char *passPhrase;
};

char* tmp_path(const char* old_path, const char *suffix){
    char* new_path;
    int len=0;
    len=strlen(old_path) + strlen(suffix) + 1;
    new_path = malloc(sizeof(char)*len);
    if(new_path == NULL){
        return NULL;
    }
    new_path[0] = '\0';
    strcat(new_path, old_path);
    strcat(new_path, suffix);
    return new_path;
}

#define BB_DATA ((struct bb_state *) fuse_get_context()->private_data)

static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, sizeof(fpath)-strlen(fpath)-1);  // ridiculously long paths will	  
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{		 	
	int res = 0;
    char fpath[PATH_MAX];
    
	bb_fullpath(fpath, path);
    
    res = lstat(fpath, stbuf);//set res to be proper file size
	
	if (res == -1)
		return -errno;

    //must return the size of the file for proper encryption
	return res;
}

static int xmp_access(const char *path, int mask)
{
	int res;
    char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
    
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
    char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
    
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
    char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
    
    
	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
    char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
	
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

	bb_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

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
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

//Changes the size of an open file
static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

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

	bb_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{      
      int res;
	  FILE *file; 
	  FILE *memoryfile;
	  char fpath[PATH_MAX];
	  ssize_t xattr_len;
	  char *memtext;
	  size_t memsize; 
	  char do_cryptVal[8];
	  int crypt_action = DONOTHING;
	
	  bb_fullpath(fpath, path);
	
	  (void) fi;
	
	  file = fopen(fpath, "r");
	  
	  if (file == NULL)
	    return -errno;
	
	  memoryfile = open_memstream(&memtext, &memsize);
	  
	  if (memoryfile == NULL)
	    return -errno;
	
	  xattr_len = getxattr(fpath, XATTR_ENCRYPTED_FLAG, do_cryptVal, 8);
	  //check if file to read has been encrypted
	  if (xattr_len != -1 && !memcmp(do_cryptVal, ENCRYPTED, 4)){
	      crypt_action = DECRYPT;
	  }
	
	  do_crypt(file, memoryfile, crypt_action, BB_DATA->passPhrase);
	  fclose(file);
	  
	  //Force open memory file to write while open
	  fflush(memoryfile);
	  fseek(memoryfile, offset, SEEK_SET);
	  res = fread(buf, 1, size, memoryfile);
	  
	  if (res == -1)
	    res = -errno;
	
	  fclose(memoryfile);
	
	  return res;
    /*
    //Void out unused params
    (void) fi;
	
	int res;
	char fpath[PATH_MAX];
	int xattrVal = 0;
    //Set initial crypt action to a pass through (dont know if encrypted or not)
    int crypt_action = DONOTHING;
    ssize_t valsize = 0;
    char *do_cryptVal[8];
    FILE *inFile = NULL;
    FILE *outFile = NULL;
    
	bb_fullpath(fpath, path);
    
    //Get xattributes to check if encrypted or not
	xattrVal = getxattr(fpath, XATTR_ENCRYPTED_FLAG, NULL, 0);

	valsize = getxattr(fpath, XATTR_ENCRYPTED_FLAG, do_cryptVal, valsize);
	
	//getattr calls lgetxattr which if false returns -1, i.e. unencrypted
	//Pass through case
	if (xattrVal < 0 || memcmp(do_cryptVal, UNENCRYPTED, 5)==0){
		printf("File unencrypted\n");		
		//Set Vars 
		//do_cryptVal keeps initialized value
		//action keeps initialized value
	}
	//Encrypted case
	else if(memcmp(do_cryptVal, ENCRYPTED,4)==0){
		printf("File encrypted\n");
		crypt_action = DECRYPT;
	}
	
	//Open files
    inFile = fopen(buf, "rb");
    if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
    }
    outFile = fopen(fpath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }
	
	//Call do_crypt for necessary encryption/decryption	
	if (!do_crypt(inFile, outFile, crypt_action, BB_DATA->passPhrase)){
         fprintf(stderr, "do_crypt failed\n");
	}
    
	fflush(outFile);
	
	//read the bytes
	res = pread(fileno(outFile), buf, size, offset);
    //fseek(outFile, 0, SEEK_END);
    //size_t tmpFilelen = ftell(outFile);
    //fseek(outFile, 0, SEEK_SET);
    
    //res = fread(buf, 1, tmpFilelen, outFile);
	
	if (res == -1)
		res = -errno;

	fclose(inFile);
	fclose(outFile);
	
	return res;
	*/
    /*
    int fd;
	int res;
    char fpath[PATH_MAX];
       
    bb_fullpath(fpath, path);
    
	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;	
	*/		  
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{		
		int res;
	    FILE *file; 
	    FILE *memoryfile;
	    char fpath[PATH_MAX];
	    ssize_t xattr_len;
	    char *memtext;
	    size_t memsize; 
	    char do_cryptVal[8];
	    int crypt_action = DONOTHING;
		
		//Call bb_fullpath to set new mirror file path				
		bb_fullpath(fpath, path);
		
		(void) fi;
		
		file = fopen(fpath, "r");
		if (file == NULL){		
		   return -errno;
	    } 
		
		memoryfile = open_memstream(&memtext, &memsize);
        if (memoryfile == NULL){
		    return -errno;
		}
		
		xattr_len = getxattr(fpath, XATTR_ENCRYPTED_FLAG, do_cryptVal, 8);
		if (xattr_len != -1 && !memcmp(do_cryptVal, ENCRYPTED, 4)){
		    crypt_action = DECRYPT;
		}
		
		//Call do_crypt to perform encryption/decryption on file to write
		do_crypt(file, memoryfile, crypt_action, BB_DATA->passPhrase);
		
		fclose(file);
		
		fseek(memoryfile, offset, SEEK_SET);
		res = fwrite(buf, 1, size, memoryfile);
		  
		if (res == -1){
		    res = -errno;
		}
		//Force file to write while open  
		fflush(memoryfile);
		
		if (crypt_action == DECRYPT) {
		    crypt_action = ENCRYPT;
		}
		
		file = fopen(fpath, "w");
		fseek(memoryfile, 0, SEEK_SET);
		
		//Now re-encrypt the file that was being written to 
		do_crypt(memoryfile, file, crypt_action, BB_DATA->passPhrase);
		
		fclose(memoryfile);
		fclose(file);
		
		return res;
		/*
		(void) fi;
		int fd;
		int res;
		int crypt_action = DONOTHING;
		char do_cryptVal[8];
	    char fpath[PATH_MAX];
	    int xattrVal = 0;
	    
		bb_fullpath(fpath, path);
	    
		//Check if file encrypted or not:
		//Unencrypted case
		if (xattrVal < 0 || memcmp(do_cryptVal, "false", 5) == 0){
			printf("Write file unencrypted, leave pass through value\n");
		}
		//Encrypted case
		else if(memcmp(do_cryptVal, ENCRYPTED,4)==0){
			printf("File encrypted\n");
			crypt_action = DECRYPT;
		}
		
	    if (crypt_action == DECRYPT)
	    {
			printf("File encrypted decrypt\n");
			FILE *inFile = NULL;
	        FILE *outFile = NULL;
	        
	        //Open files
		    inFile = fopen(buf, "rb");
		    if(!inFile){
			    perror("infile fopen error");
				return EXIT_FAILURE;
		    }
		    
		    outFile = fopen(fpath, "wb+");
		    if(!outFile){
				perror("outfile fopen error");
				return EXIT_FAILURE;
		    }
	        if(!do_crypt(inFile, outFile, DECRYPT, BB_DATA->passPhrase)){
			     fprintf(stderr, "WRITE: do_crypt failed\n");
		    }
			
			res = pwrite(fileno(outFile), buf, size, offset);
			if (res == -1)
				res = -errno;
		    
		   //Encrypt the contents
			if(!do_crypt(outFile, inFile, ENCRYPT, BB_DATA->passPhrase)){
			     fprintf(stderr, "WRITE: do_crypt failed\n");
			}
		    
		    fclose(inFile);
		    fclose(outFile);
		}
		//Unencrypted case
		else if (crypt_action == DONOTHING)
		{
		     //File is unencrypted
	
			fd = open(fpath, O_WRONLY);
			if (fd == -1)
				return -errno;
	
			res = pwrite(fd, buf, size, offset);
			if (res == -1)
				res = -errno;
	
			close(fd);	
		}
	
	return res;
    */
	/*
	  int res;
	  char fpath[PATH_MAX];
	  FILE *f, *memfile;
	  char *memtext;
	  size_t memsize;
	  int crypt_action = DONOTHING;
	  char do_cryptVal[8];
	  ssize_t xattr_len;
	
	  bb_fullpath(fpath, path);
	
	  (void) fi;
	
	  f = fopen(fpath, "r");
	  if (f == NULL)
	    return -errno;
	
	  memfile = open_memstream(&memtext, &memsize);
	  if (memfile == NULL)
	    return -errno;
	
	  xattr_len = getxattr(fpath, XATTR_ENCRYPTED_FLAG, do_cryptVal, 8);
	  if (xattr_len != -1 && !memcmp(do_cryptVal, ENCRYPTED, 4)){
	    crypt_action = DECRYPT;
	  }
	
	  do_crypt(f, memfile, crypt_action, BB_DATA->passPhrase);
	  fclose(f);
	
	  fseek(memfile, offset, SEEK_SET);
	  res = fwrite(buf, 1, size, memfile);
	  if (res == -1)
	    res = -errno;
	  fflush(memfile);
	  //Encrypt the edited file
	  if (crypt_action == DECRYPT) {
	    crypt_action = ENCRYPT;
	  }
	
	  f = fopen(fpath, "w");
	  fseek(memfile, 0, SEEK_SET);
	  do_crypt(memfile, f, crypt_action, BB_DATA->passPhrase);
	
	  fclose(memfile);
	  fclose(f);
	
	  return res;*/	 	  
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{  
    //void out unused paramaters
    (void) fi;
    (void) mode;
    char fpath[PATH_MAX];

	bb_fullpath(fpath, path); 
    FILE *outFile = fopen(fpath, "wb+");
    
    //Create an encrypted file
    if (!do_crypt(outFile, outFile, ENCRYPT, BB_DATA->passPhrase)){
		printf("do_crypt failed\n");
	}
	//close the file
	fclose(outFile);
	
	//set the xattributes to show encryption
	if(setxattr(fpath, XATTR_ENCRYPTED_FLAG, ENCRYPTED, 4, 0)){
		return -errno;
	}
	
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
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
	
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
	
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
	
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];

	bb_fullpath(fpath, path);
	
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
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
    //umask(0);//Tells all files created to have no revoked priveleges   
    int fuse_stat;
    struct bb_state *bb_data;
    
    if (argc < 4)
    {
		printf("Not enough arguments, please run with:\n ./pa4-encs <passPhrase> <rootdir> <mountdir>\n");
		printf("exiting...\n");
		exit(EXIT_FAILURE);
	}
    
    //From tutorial: Disallow root from mounting
    if ((getuid() == 0) || (geteuid() == 0)) {
	   fprintf(stderr, "Running ENCFS as root opens unnacceptable security holes\n");
       return 1;
    }

	bb_data = malloc(sizeof(struct bb_state));
    
    if (bb_data == NULL) {
	    perror("main calloc");
	    abort();
    }
       
    //Malloc the data pointer
    //xmp_data = malloc(sizeof(struct xmp_state));
    
    // Pull the rootdir out of the argument list and save it in the
    // internal data, realpath is a c command sets the root directory for you
    bb_data->rootdir = realpath(argv[argc-2], NULL);//Set root directory
    bb_data->passPhrase = argv[argc-3];//set passPhrase
    
    //Move arguments into place so referencing is done correctly
    argv[argc-3] = argv[argc-1];
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc = argc - 2;
    
	//Create the mirrored directory with xmp_data
	// turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &xmp_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
			
	return fuse_stat;
}
