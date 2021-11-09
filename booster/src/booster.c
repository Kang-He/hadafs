/*
   Copyright (c) 2007-2009 HADA, Inc. <http://www.hada.com>
   This file is part of HADAFS.

   HADAFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   HADAFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libhadafsclient.h>
#include <list.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <logging.h>
#include <utime.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include "booster-fd.h"

#ifndef GF_UNIT_KB
#define GF_UNIT_KB 1024
#endif

/* attr constructor registers this function with libc's
 * _init function as a function that must be called before
 * the main() of the program.
 */
static void booster_lib_init (void) __attribute__((constructor));

extern fd_t *
fd_ref (fd_t *fd);

extern void
fd_unref (fd_t *fd);

extern int pipe (int filedes[2]);
/* We define these flags so that we can remove fcntl.h from the include path.
 * fcntl.h has certain defines and other lines of code that redirect the
 * application's open and open64 calls to the syscalls defined by
 * libc, for us, thats not a Good Thing (TM).
 */
#ifndef GF_O_CREAT
#define GF_O_CREAT      0x40
#endif

#ifndef GF_O_TRUNC
#define GF_O_TRUNC      0x200
#endif

#ifndef GF_O_RDWR
#define GF_O_RDWR       0x2
#endif

#ifndef GF_O_WRONLY
#define GF_O_WRONLY     0x1
#endif

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

typedef enum {
        BOOSTER_OPEN,
        BOOSTER_CREAT
} booster_op_t;

struct _object;
struct _dict;

ssize_t
write (int fd, const void *buf, size_t count);

/* open, open64, creat */
static int (*real_open) (const char *pathname, int flags, ...);
static int (*real_open64) (const char *pathname, int flags, ...);
static int (*real_creat) (const char *pathname, mode_t mode);

/* read, readv*/
static ssize_t (*real_read) (int fd, void *buf, size_t count);
static ssize_t (*real_readv) (int fd, const struct iovec *vector, int count);

/* write, writev*/
static ssize_t (*real_write) (int fd, const void *buf, size_t count);
static ssize_t (*real_writev) (int fd, const struct iovec *vector, int count);

/* flush */
static int (*real_flush) (int fd);

/* ioctl */
static int (*real_ioctl) (int fd, uint32_t cmd, uint64_t arg);

/* lseek */
static off_t (*real_lseek) (int fd, unsigned long offset, int whence);
static off_t (*real_lseek64) (int fd, uint64_t offset, int whence);

/* close */
static int (*real_close) (int fd);

/* dup dup2 */
static int (*real_dup) (int fd);
static int (*real_dup2) (int oldfd, int newfd);

/* unlink */
static int (*real_unlink) (const char *path);

/* stat */
static int (*real___xstat) (int ver, const char *path, struct stat *buf);
static int (*real___xstat64) (int ver, const char *path, struct stat64 *buf);
static int (*real_stat) (const char *path, struct stat *buf);
static int (*real_stat64) (const char *path, struct stat64 *buf);
static int (*real___fxstat) (int ver, int fd, struct stat *buf);
static int (*real___fxstat64) (int ver, int fd, struct stat64 *buf);
static int (*real_fstat) (int fd, struct stat *buf);
static int (*real_fstat64) (int fd , struct stat64 *buf);

static pid_t (*real_fork) (void);

#define RESOLVE(sym) do {                                       \
                if (!real_##sym)                                \
                        real_##sym = dlsym (RTLD_NEXT, #sym);   \
        } while (0)

/*TODO: set proper value */
#define MOUNT_HASH_SIZE 256

struct booster_mount {
        dev_t st_dev;
        hadafs_handle_t handle;
        struct list_head device_list;
};
typedef struct booster_mount booster_mount_t;

static booster_fdtable_t *booster_fdtable = NULL;

extern int booster_configure (char *confpath);
/* This is dup'ed every time VMP open/creat wants a new fd.
 * This is needed so we occupy an entry in the process' file
 * table.
 */
int process_piped_fd = -1;

static int
booster_get_process_fd ()
{
        return real_dup (process_piped_fd);
}

/* The following two define which file contains
 * the FSTAB configuration for VMP-based usage.
 */
#define DEFAULT_BOOSTER_CONF    CONFDIR"/booster.conf"
#define BOOSTER_CONF_ENV_VAR    "HADAFS_BOOSTER_FSTAB"


/* The following define which log file is used when
 * using the old mount point bypass approach.
 */
#define BOOSTER_DEFAULT_LOG     CONFDIR"/booster.log"
#define BOOSTER_LOG_ENV_VAR     "HADAFS_BOOSTER_LOG"

void
do_open (int fd, const char *pathname, int flags, mode_t mode, booster_op_t op)
{
        char                   *specfile = NULL;
        char                   *mount_point = NULL; 
        int32_t                 size = 0;
        int32_t                 ret = -1;
        FILE                   *specfp = NULL;
        hadafs_file_t        fh = NULL;
        char                   *logfile = NULL;
        hadafs_init_params_t iparams = {
                .loglevel = "error",
        };
      
        gf_log ("booster", GF_LOG_DEBUG, "Opening using MPB: %s", pathname);
        size = fgetxattr (fd, "user.hadafs-booster-volfile", NULL, 0);
        if (size == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Xattr "
                        "user.hadafs-booster-volfile not found: %s",
                        strerror (errno));
                goto out;
        }
		
        specfile = calloc (1, size);
        if (!specfile) {
                gf_log ("booster", GF_LOG_ERROR, "Memory allocation failed");
                goto out;
        }

        ret = fgetxattr (fd, "user.hadafs-booster-volfile", specfile,
                         size);
        if (ret == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Xattr "
                        "user.hadafs-booster-volfile not found: %s",
                        strerror (errno));
                goto out;
        }
    
        specfp = tmpfile ();
        if (!specfp) {
                gf_log ("booster", GF_LOG_ERROR, "Temp file creation failed"
                        ": %s", strerror (errno));
                goto out;
        }

        ret = fwrite (specfile, size, 1, specfp);
        if (ret != 1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to write volfile: %s",
                        strerror (errno));
                goto out;
        }
		
        fseek (specfp, 0L, SEEK_SET);

        size = fgetxattr (fd, "user.hadafs-booster-mount", NULL, 0);
        if (size == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Xattr "
                        "user.hadafs-booster-mount not found: %s",
                        strerror (errno));
                goto out;
        }
        
        mount_point = calloc (size, sizeof (char));
        if (!mount_point) {
                gf_log ("booster", GF_LOG_ERROR, "Memory allocation failed");
                goto out;
        }
	
        ret = fgetxattr (fd, "user.hadafs-booster-mount", mount_point, size);
        if (ret == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Xattr "
                        "user.hadafs-booster-mount not found: %s",
                        strerror (errno));
                goto out;
        }

        logfile = getenv (BOOSTER_LOG_ENV_VAR);
        if (logfile) {
                if (strlen (logfile) > 0)
                        iparams.logfile = strdup (logfile);
                else
                        iparams.logfile = strdup (BOOSTER_DEFAULT_LOG);
        } else {
                iparams.logfile = strdup (BOOSTER_DEFAULT_LOG);
        }

        gf_log ("booster", GF_LOG_TRACE, "Using log-file: %s", iparams.logfile);
        iparams.specfp = specfp;

        ret = hadafs_mount_old (mount_point, &iparams);
        if (ret == -1) {
                if (errno != EEXIST) {
                        gf_log ("booster", GF_LOG_ERROR, "Mount failed over"
                                " hadafs");
                        goto out;
                } else
                        gf_log ("booster", GF_LOG_ERROR, "Already mounted");
        }

        switch (op) {
        case BOOSTER_OPEN:
                gf_log ("booster", GF_LOG_TRACE, "Booster open call");
                fh = hadafs_open (pathname, flags, mode);
                break;
        case BOOSTER_CREAT:
		/* 
		* change create to open , with O_RDWR|O_CTREA default
		* flags
		 */
                gf_log ("booster", GF_LOG_TRACE, "Booster create call");
                fh = hadafs_open (pathname, O_RDWR|O_CREAT, mode);
                break;
        }

        if (!fh) {
                gf_log ("booster", GF_LOG_ERROR, "Error performing operation");
                goto out;
        }

        if (booster_fd_unused_get (booster_fdtable, fh, fd) == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to get unused FD");
                goto out;
        }
        fh = NULL;

out:
        if (specfile) {
                free (specfile);
        }

        if (specfp) {
                fclose (specfp);
        }

        if (mount_point) {
                free (mount_point);
        }

        if (fh) {
                hadafs_close (fh);
        }

        return;
}

int
vmp_open (const char *pathname, int flags, ...)
{
        mode_t                  mode = 0;
        int                     fd = -1;
        hadafs_file_t        fh = NULL;
        va_list                 ap;

        if (flags & GF_O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);
                fh = hadafs_open (pathname, flags, mode);
        }
        else
                fh = hadafs_open (pathname, flags);

        if (!fh) {
                gf_log ("booster", GF_LOG_ERROR, "VMP open failed");
                goto out;
        }

        fd = booster_get_process_fd ();
        if (fd == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to create open fd");
                goto fh_close_out;
        }

        if (booster_fd_unused_get (booster_fdtable, fh, fd) == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to map fd into table");
                goto realfd_close_out;
        }

        return fd;

realfd_close_out:
        real_close (fd);
        fd = -1;

fh_close_out:
        hadafs_close (fh);

out:
        return fd;
}

#define BOOSTER_USE_OPEN64          1
#define BOOSTER_DONT_USE_OPEN64     0

int
booster_open (const char *pathname, int use64, int flags, ...)
{
        int     ret = -1;
        mode_t  mode = 0;
        va_list ap;
        int     (*my_open) (const char *pathname, int flags, ...);

        if (!pathname) {
                errno = EINVAL;
                goto out;
        }

        gf_log ("booster", GF_LOG_TRACE, "Open: %s", pathname);
        /* First try opening through the virtual mount point.
         * The difference lies in the fact that:
         * 1. We depend on libhadafsclient library to perform
         * the translation from the path to handle.
         * 2. We do not go to the file system for the fd, instead
         * we use booster_get_process_fd (), which returns a dup'ed
         * fd of a pipe created in booster_init.
         */
        if (flags & GF_O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);
                ret = vmp_open (pathname, flags, mode);
        }
        else
                ret = vmp_open (pathname, flags);

        /* We receive an ENODEV if the VMP does not exist. If we
         * receive an error other than ENODEV, it means, there
         * actually was an error performing vmp_open. This must
         * be returned to the user.
         */
        if ((ret < 0) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "Error in opening file over "
                        " VMP: %s", strerror (errno));
                goto out;
        }

        if (ret > 0) {
                gf_log ("booster", GF_LOG_TRACE, "File opened");
                goto out;
        }

        if (use64) {
                gf_log ("booster", GF_LOG_TRACE, "Using 64-bit open");
		my_open = real_open64;
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Using 32-bit open");
		my_open = real_open;
        }

        /* It is possible the RESOLVE macro is not able
         * to resolve the symbol of a function, in that case
         * we dont want to seg-fault on calling a NULL functor.
         */
        if (my_open == NULL) {
                gf_log ("booster", GF_LOG_ERROR, "open not resolved");
                ret = -1;
                errno = ENOSYS;
                goto out;
        }

	if (flags & GF_O_CREAT) {
		va_start (ap, flags);
		mode = va_arg (ap, mode_t);
		va_end (ap);

                ret = my_open (pathname, flags, mode);
	} else
                ret = my_open (pathname, flags);

        if (ret != -1) {
                gf_log ("booster", GF_LOG_TRACE, "my_open: %s ok", pathname);
		//do_open (ret, pathname, flags, mode, BOOSTER_OPEN);
        }

out:
        return ret;
}

/* This is done to over-write existing definitions of open and open64 inside
 * libc with our own copies. __REDIRECT is provided by libc.
 *
 * XXX: This will not work anywhere other than libc based systems.
 */
int __REDIRECT (booster_false_open, (__const char *__file, int __oflag, ...),
                open) __nonnull ((1));
int __REDIRECT (booster_false_open64, (__const char *__file, int __oflag, ...),
                open64) __nonnull ((1));
int
booster_false_open (const char *pathname, int flags, ...)
{
        int     ret;
        mode_t  mode = 0;
        va_list ap;

        if (flags & GF_O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);

                ret = booster_open (pathname, BOOSTER_DONT_USE_OPEN64, flags,
                                    mode);
        }
        else
                ret = booster_open (pathname, BOOSTER_DONT_USE_OPEN64, flags);

        return ret;
}

int
booster_false_open64 (const char *pathname, int flags, ...)
{
        int     ret;
        mode_t  mode = 0;
        va_list ap;

        if (flags & GF_O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);

                ret = booster_open (pathname, BOOSTER_USE_OPEN64, flags, mode);
        }
        else
                ret = booster_open (pathname, BOOSTER_USE_OPEN64, flags);

        return ret;
}

int
vmp_creat (const char *pathname, mode_t mode)
{
        int                     fd = -1;
        hadafs_file_t        fh = NULL;

        fh = hadafs_open (pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
        if (!fh) {
                gf_log ("booster", GF_LOG_ERROR, "Create failed: %s: %s",
                        pathname, strerror (errno));
                goto out;
        }

        fd = booster_get_process_fd ();
        if (fd == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to create fd");
                goto close_out;
        }

        if ((booster_fd_unused_get (booster_fdtable, fh, fd)) == -1) {
                gf_log ("booster", GF_LOG_ERROR, "Failed to map unused fd");
                goto real_close_out;
        }

        return fd;

real_close_out:
        real_close (fd);
        fd = -1;

close_out:
        hadafs_close (fh);

out:
        return -1;
}

int __REDIRECT (booster_false_creat, (const char *pathname, mode_t mode),
                creat) __nonnull ((1));

int
booster_false_creat (const char *pathname, mode_t mode)
{
        int     ret = -1;
        if (!pathname) {
                errno = EINVAL;
                goto out;
        }

        gf_log ("booster", GF_LOG_TRACE, "Create: %s", pathname);
        ret = vmp_creat (pathname, mode);

        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "VMP create failed: %s",
                        strerror (errno));
                goto out;
        }

        if (ret > 0) {
                gf_log ("booster", GF_LOG_TRACE, "File created");
                goto out;
        }

        if (real_creat == NULL) {
                errno = ENOSYS;
                ret = -1;
                goto out;
        }

        ret = real_creat (pathname, mode);

        if (ret != -1) {
                do_open (ret, pathname, GF_O_WRONLY | GF_O_TRUNC, mode,
                         BOOSTER_CREAT);
        } else
                gf_log ("booster", GF_LOG_ERROR, "real create failed: %s",
                        strerror (errno));

out:
        return ret;
}

ssize_t
read (int fd, void *buf, size_t count)
{
        int ret;
        hadafs_file_t glfs_fd;

        gf_log ("booster", GF_LOG_TRACE, "read: fd %d, count %lu", fd,
                (long unsigned)count);
        glfs_fd = booster_fdptr_get (booster_fdtable, fd);
        if (!glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Not booster fd");
                if (real_read == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_read (fd, buf, count);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_read (glfs_fd, buf, count);
                booster_fdptr_put (glfs_fd);
        }

        return ret;
}


ssize_t
readv (int fd, const struct iovec *vector, int count)
{
        int ret;
        hadafs_file_t glfs_fd = 0;

        gf_log ("booster", GF_LOG_TRACE, "readv: fd %d, iovecs %d", fd, count);
        glfs_fd = booster_fdptr_get (booster_fdtable, fd);
        if (!glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_readv == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_readv (fd, vector, count);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
		ret = hadafs_readv (glfs_fd, vector, count);
                booster_fdptr_put (glfs_fd);
        }

        return ret;
}


ssize_t
write (int fd, const void *buf, size_t count)
{
        int ret;
        hadafs_file_t glfs_fd = 0;

        gf_log ("booster", GF_LOG_TRACE, "write: fd %d, count %d", fd, count);

        glfs_fd = booster_fdptr_get (booster_fdtable, fd);

        if (!glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_write == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_write (fd, buf, count);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_write (glfs_fd, buf, count);
                booster_fdptr_put (glfs_fd);
        }
 
        return ret;
}

ssize_t
writev (int fd, const struct iovec *vector, int count)
{
        int ret = 0;
        hadafs_file_t glfs_fd = 0; 

        gf_log ("booster", GF_LOG_TRACE, "writev: fd %d, iovecs %d", fd, count);
        glfs_fd = booster_fdptr_get (booster_fdtable, fd);

        if (!glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_writev == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_writev (fd, vector, count);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_writev (glfs_fd, vector, count);
                booster_fdptr_put (glfs_fd);
        }

        return ret;
}

off_t
lseek (int fd, unsigned long offset, int whence)
{
        int ret;
        hadafs_file_t glfs_fd = 0;

        gf_log ("booster", GF_LOG_TRACE, "lseek: fd %d, offset %ld",
                fd, offset);

        glfs_fd = booster_fdptr_get (booster_fdtable, fd);
        if (glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_lseek (glfs_fd, offset, whence);
                booster_fdptr_put (glfs_fd);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_lseek == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_lseek (fd, offset, whence);
        }

        return ret;
}

off_t
lseek64 (int fd, uint64_t offset, int whence)
{
        int ret;
        hadafs_file_t glfs_fd = 0;


        gf_log ("booster", GF_LOG_TRACE, "lseek: fd %d, offset %"PRIu64,
               	fd, offset);
        glfs_fd = booster_fdptr_get (booster_fdtable, fd);
        if (glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_lseek (glfs_fd, offset, whence);
                booster_fdptr_put (glfs_fd);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_lseek64 == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_lseek64 (fd, offset, whence);
        }

        return ret;
}

int
close (int fd)
{
        int ret = -1;
        hadafs_file_t glfs_fd = 0;

        gf_log ("booster", GF_LOG_TRACE, "close: fd %d", fd);
	glfs_fd = booster_fdptr_get (booster_fdtable, fd);
    
	if (glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
		booster_fd_put (booster_fdtable, fd);
		ret = hadafs_close (glfs_fd);
		booster_fdptr_put (glfs_fd);
	}

        ret = real_close (fd);

        return ret;
}

int
flush (int fd)
{
        int                     ret = -1;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "fsync: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_flush == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_flush (fd);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_flush (fh);
                booster_fdptr_put (fh);
        }

        return ret;
}

int
ioctl (int fd, uint32_t cmd, uint64_t arg)
{
        int                     ret = -1;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "ioctl: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_ioctl == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                } else
                        ret = real_ioctl (fd, cmd, arg);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_ioctl (fh, cmd, arg);
                booster_fdptr_put (fh);
        }

        return ret;
}

int 
dup (int oldfd)
{
        int ret = -1, new_fd = -1;
        hadafs_file_t glfs_fd = 0;

        gf_log ("booster", GF_LOG_TRACE, "dup: fd %d", oldfd);
        glfs_fd = booster_fdptr_get (booster_fdtable, oldfd);
        new_fd = real_dup (oldfd);

        if (new_fd >=0 && glfs_fd) {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = booster_fd_unused_get (booster_fdtable, glfs_fd,
                                             new_fd);
                fd_ref ((fd_t *)glfs_fd);
                if (ret == -1) {
                        gf_log ("booster", GF_LOG_ERROR,"Failed to map new fd");
                        real_close (new_fd);
                } 
        }

        if (glfs_fd) {
                booster_fdptr_put (glfs_fd);
        }

        return new_fd;
}

int 
dup2 (int oldfd, int newfd)
{
        int ret = -1;
        hadafs_file_t old_glfs_fd = NULL, new_glfs_fd = NULL;

        if (oldfd == newfd) {
                return newfd;
        }

        old_glfs_fd = booster_fdptr_get (booster_fdtable, oldfd);
        new_glfs_fd = booster_fdptr_get (booster_fdtable, newfd);
 
        ret = real_dup2 (oldfd, newfd); 
        if (ret >= 0) {
                if (new_glfs_fd) {
                        hadafs_close (new_glfs_fd);
                        booster_fdptr_put (new_glfs_fd);
                        booster_fd_put (booster_fdtable, newfd);
                        new_glfs_fd = 0;
                }

                if (old_glfs_fd) {
                        ret = booster_fd_unused_get (booster_fdtable,
                                                     old_glfs_fd, newfd);
                        fd_ref ((fd_t *)old_glfs_fd);
                        if (ret == -1) {
                                real_close (newfd);
                        }
                }
        } 

        if (old_glfs_fd) {
                booster_fdptr_put (old_glfs_fd);
        }

        if (new_glfs_fd) {
                booster_fdptr_put (new_glfs_fd);
        }

        return ret;
}

int
unlink (const char *path)
{
        int     ret = -1;
        gf_log ("booster", GF_LOG_TRACE, "unlink: path %s", path);
        ret = hadafs_unlink (path);
        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "unlink failed: %s",
                        strerror (errno));
                return ret;
        }

        if (ret == 0) {
                gf_log ("booster", GF_LOG_TRACE, "unlink succeeded");
                return ret;
        }

        if (real_unlink == NULL) {
                errno = ENOSYS;
                ret = -1;
        } else
                ret = real_unlink (path);

        return ret;
}

/* The real stat functions reside in booster_stat.c to
 * prevent clash with the statX prototype and functions
 * declared from sys/stat.h
 */
int
booster_xstat (int ver, const char *path, void *buf)
{
        struct stat     *sbuf = (struct stat *)buf;
        int             ret = -1;

        gf_log ("booster", GF_LOG_TRACE, "xstat: path: %s", path);
        ret = hadafs_stat (path, sbuf);
        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "xstat failed: %s",
                        strerror (errno));
                goto out;
        }

        if (ret == 0) {
                gf_log ("booster", GF_LOG_TRACE, "xstat succeeded");
                goto out;
        }

        if (real___xstat == NULL) {
                ret = -1;
                errno = ENOSYS;
                goto out;
        }

        ret = real___xstat (ver, path, sbuf);
out:
        return ret;
}

int
booster_xstat64 (int ver, const char *path, void *buf)
{
        int             ret = -1;
        struct stat64   *sbuf = (struct stat64 *)buf;

        gf_log ("booster", GF_LOG_TRACE, "xstat64: path: %s", path);
        ret = hadafs_stat (path, (struct stat *)sbuf);
        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "xstat64 failed: %s",
                        strerror (errno));
                goto out;
        }

        if (ret == 0) {
                gf_log ("booster", GF_LOG_TRACE, "xstat64 succeeded");
                goto out;
        }

        if (real___xstat64 == NULL) {
                errno = ENOSYS;
                ret = -1;
                goto out;
        }

        ret = real___xstat64 (ver, path, sbuf);
out:
        return ret;
}


int
booster_stat (const char *path, void *buf)
{
        struct stat     *sbuf = (struct stat *)buf;
        int             ret = -1;

        gf_log ("booster", GF_LOG_TRACE, "stat: path: %s", path);
        ret = hadafs_stat (path, sbuf);
        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "stat failed: %s",
                        strerror (errno));
                goto out;
        }

        if (ret == 0) {
                gf_log ("booster", GF_LOG_TRACE, "stat succeeded");
                goto out;
        }

        if (real_stat != NULL)
                ret = real_stat (path, sbuf);
        else if (real___xstat != NULL)
                ret = real___xstat (0, path, sbuf);
        else {
                errno = ENOSYS;
                ret = -1;
                goto out;
        }

out:
        return ret;
}

int
booster_stat64 (const char *path, void *buf)
{
        int             ret = -1;
        struct stat64   *sbuf = (struct stat64 *)buf;

        gf_log ("booster", GF_LOG_TRACE, "stat64: %s", path);
        ret = hadafs_stat (path, (struct stat *)sbuf);
        if ((ret == -1) && (errno != ENODEV)) {
                gf_log ("booster", GF_LOG_ERROR, "stat64 failed: %s",
                        strerror (errno));
                goto out;
        }

        if (ret == 0) {
                gf_log ("booster", GF_LOG_TRACE, "stat64 succeeded");
                goto out;
        }

        if (real_stat64 != NULL)
                ret = real_stat64 (path, sbuf);
        else if (real___xstat64 != NULL)
                ret = real___xstat64 (0, path, sbuf);
        else {
                errno = ENOSYS;
                ret = -1;
                goto out;
        }

out:
        return ret;
}

int
booster_fxstat (int ver, int fd, void *buf)
{
        struct stat             *sbuf = (struct stat *)buf;
        int                     ret = -1;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "fxstat: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real___fxstat == NULL) {
                        errno = ENOSYS;
                        ret = -1;
                        goto out;
                }

                ret = real___fxstat (ver, fd, sbuf);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_fstat (fh, sbuf);
                booster_fdptr_put (fh);
        }

out:
        return ret;
}

int
booster_fxstat64 (int ver, int fd, void *buf)
{
        int                     ret = -1;
        struct stat64           *sbuf = (struct stat64 *)buf;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "fxstat64: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real___fxstat64 == NULL) {
                        ret = -1;
                        errno = ENOSYS;
                        goto out;
                }
                ret = real___fxstat64 (ver, fd, sbuf);
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_fstat (fh, (struct stat *)sbuf);
                booster_fdptr_put (fh);
        }

out:
        return ret;
}

int
booster_fstat (int fd, void *buf)
{
        struct stat             *sbuf = (struct stat *)buf;
        int                     ret = -1;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "fstat: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_fstat != NULL)
                        ret = real_fstat (fd, sbuf);
                else if (real___fxstat != NULL)
                        ret = real___fxstat (0, fd, sbuf);
                else {
                        ret = -1;
                        errno = ENOSYS;
                        goto out;
                }
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_fstat (fh, sbuf);
                booster_fdptr_put (fh);
        }

out:
        return ret;
}

int
booster_fstat64 (int fd, void *buf)
{
        int                     ret = -1;
        struct stat64           *sbuf = (struct stat64 *)buf;
        hadafs_file_t        fh = NULL;

        gf_log ("booster", GF_LOG_TRACE, "fstat64: fd %d", fd);
        fh = booster_fdptr_get (booster_fdtable, fd);
        if (!fh) {
                gf_log ("booster", GF_LOG_TRACE, "Not a booster fd");
                if (real_fstat64 != NULL)
                        ret = real_fstat64 (fd, sbuf);
                else if (real___fxstat64 != NULL)
                        /* Not sure how portable the use of 0 for
                         * version number is but it works over glibc.
                         * We need this because, I've
                         * observed that all the above real* functors can be
                         * NULL. In that case, this is our last and only option.
                         */
                        ret = real___fxstat64 (0, fd, sbuf);
                else {
                        ret = -1;
                        errno = ENOSYS;
                        goto out;
                }
        } else {
                gf_log ("booster", GF_LOG_TRACE, "Is a booster fd");
                ret = hadafs_fstat (fh, (struct stat *)sbuf);
                booster_fdptr_put (fh);
        }

out:
        return ret;
}

#define MOUNT_TABLE_HASH_SIZE 256

static void booster_cleanup (void);
static int 
booster_init (void)
{
        char    *booster_conf_path = NULL;
        int     ret = -1;
        int     pipefd[2];

        booster_fdtable = booster_fdtable_alloc ();
        if (!booster_fdtable) {
                fprintf (stderr, "cannot allocate fdtable: %s\n",
                         strerror (errno));
		goto err;
        }
 
        if (pipe (pipefd) == -1) {
                fprintf(stderr, "Pipe creation failed:%s"
                        , strerror (errno));
                goto err;
        }

        process_piped_fd = pipefd[0];
        real_close (pipefd[1]);
        /* libhadafsclient based VMPs should be inited only
         * after the file tables are inited so that if the socket
         * calls use the fd based syscalls, the fd tables are
         * correctly initialized to return a NULL handle, on which the
         * socket calls will fall-back to the real API.
         */
        booster_conf_path = getenv (BOOSTER_CONF_ENV_VAR);
        if (booster_conf_path != NULL) {
                if (strlen (booster_conf_path) > 0)
                        ret = booster_configure (booster_conf_path);
                else {
                        gf_log ("booster", GF_LOG_ERROR, "%s not defined, "
                                "using default path: %s", BOOSTER_CONF_ENV_VAR,
                                DEFAULT_BOOSTER_CONF);
                        ret = booster_configure (DEFAULT_BOOSTER_CONF);
                }
        } else {
                gf_log ("booster", GF_LOG_ERROR, "%s not defined, using default"
                        " path: %s", BOOSTER_CONF_ENV_VAR,DEFAULT_BOOSTER_CONF);
                ret = booster_configure (DEFAULT_BOOSTER_CONF);
        }

        atexit (booster_cleanup);
        if (ret == 0)
                gf_log ("booster", GF_LOG_DEBUG, "booster is inited");
	return 0;

err:
        /* Sure we return an error value here
         * but who cares about booster.
         */
	return -1; 
}


static void
booster_cleanup (void)
{
        /* Ideally, we should be de-initing the fd-table
         * here but the problem is that I've seen file accesses through booster
         * continuing while the atexit registered function is called. That means
         * , we cannot dealloc the fd-table since then there could be a crash
         * while trying to determine whether a given fd is for libc or for
         * libhadafsclient.
         * We should be satisfied with having cleaned up hadafs contexts.
         */
        hadafs_umount_all ();
	hadafs_reset ();
}



pid_t 
fork (void)
{
	pid_t pid = 0;
	char child = 0;

	hadafs_log_lock ();
	{
		pid = real_fork ();
	}
	hadafs_log_unlock ();

	child = (pid == 0);
	if (child) {
		booster_cleanup ();
		booster_init ();
	}

	return pid;
}

void
booster_lib_init (void)
{

        RESOLVE (open);
        RESOLVE (open64);
        RESOLVE (creat);

        RESOLVE (read);
        RESOLVE (readv);

        RESOLVE (write);
        RESOLVE (writev);
        RESOLVE (close);
	RESOLVE (flush);
	RESOLVE (ioctl);

	RESOLVE (unlink);

	RESOLVE (__xstat);
        RESOLVE (__xstat64);
        RESOLVE (stat);
        RESOLVE (stat64);
        RESOLVE (__fxstat);
        RESOLVE (__fxstat64);
        RESOLVE (fstat);
        RESOLVE (fstat64);
        
	RESOLVE (lseek);
	RESOLVE (lseek64);	

        RESOLVE (dup);
        RESOLVE (dup2);

	RESOLVE (fork); 


        /* This must be called after resolving real functions
         * above so that the socket based IO calls in libglusterfsclient
         * can fall back to a non-NULL real_XXX function pointer.
         * Calling booster_init before resolving the names above
         * results in seg-faults because the function symbols above are NULL.
         */
	booster_init ();
}
