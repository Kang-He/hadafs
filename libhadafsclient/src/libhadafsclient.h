/*
  Copyright (c) 2008, 2009 HADA, Inc. <http://www.hada.com>
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

#ifndef _LIBHADAFSCLIENT_H
#define _LIBHADAFSCLIENT_H

#ifndef __BEGIN_DECLS
#ifdef __cplusplus
#define __BEGIN_DECLS extern "C" {
#else
#define __BEGIN_DECLS
#endif
#endif

#ifndef __END_DECLS
#ifdef __cplusplus
#define __END_DECLS }
#else
#define __END_DECLS
#endif
#endif


__BEGIN_DECLS

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <utime.h>
#include <sys/time.h>
#include <stdint.h>

typedef enum {
	RW,
	RO,
} hadafs_mounttype_t;

typedef struct {
        struct iovec *vector;
        int           count;
        void         *iobref;
        void         *dictref;
} hadafs_iobuf_t;


typedef
int (*hadafs_readv_cbk_t) (int op_ret, int op_errno, hadafs_iobuf_t *buf,
			      void *cbk_data);

typedef
int (*hadafs_write_cbk_t) (int op_ret, int op_errno, void *cbk_data);

typedef
int (*hadafs_get_cbk_t) (int op_ret, int op_errno, hadafs_iobuf_t *buf,
			    struct stat *stbuf, void *cbk_data);


/* Data Interface
 * The first section describes the data structures required for
 * using libhadafsclient.
 */

/* This structure needs to be filled up and
 * passed to te hadafs_init function which uses
 * the params passed herein to initialize a hadafs
 * client context and then connect to a hadafs server.
 */
typedef struct {
        char          *logfile;         /* Path to the file which will store
                                           the log.
                                           */
        char          *loglevel;        /* The log level required for
                                           reporting various events within
                                           libhadafsclient.
                                           */
        struct {
                char  *specfile;        /* Users can either open a volume or
                                           specfile and assign the pointer to
                                           specfp, or just refer to the volume
                                           /spec file path in specfile.
                                           */
                FILE  *specfp;
        };
        char          *volume_name;     /* The volume file could describe many
                                           volumes but the specific volume
                                           within that file is chosen by
                                           specifying the volume name here.
                                           */

	uid_t         muid;
	gid_t         mgid;
	mode_t        mmode;             /* The mntpoint accessing mode defined in client*/
        int            relativepaths;

} hadafs_init_params_t;



/* This is the handle returned by hadafs_init
 * once the initialization is complete.
 * Users should treat this as an opaque handle.
 */
typedef void * hadafs_handle_t;



/* These identifiers are used as handles for files and dirs.
 * Users of libhadafsclient should not in anyway try to interpret
 * the actual structures these will point to.
 */
typedef void * hadafs_file_t;
typedef void * hadafs_dir_t;


/* Function Call Interface */
/* libhadafsclient initialization function.
 * @ctx : the structure described above filled with required values.
 * @fakefsid: User generated fsid to be used to identify this
 * volume.
 *
 * Returns NULL on failure and the non-NULL pointer on success.
 * On failure, the error description might be present in the logfile
 * depending on the log level.
 */
hadafs_handle_t
hadafs_init (hadafs_init_params_t *ctx, uint32_t fakefsid);



/* Used to destroy a hadafs client context and the
 * connection to the hadafs server.
 *
 * @handle      : The hadafs handle returned by hadafs_init.
 */
int
hadafs_fini (hadafs_handle_t handle);



/* libhadafs client provides two interfaces.
 * 1. handle-based interface
 * Functions that comprise the handle-based interface accept the
 * hadafs_handle_t as the first argument. It specifies the
 * hadafs client context over which to perform the operation.
 *
 * 2. Virtual Mount Point based interface:
 * Functions that do not require a handle to be given in order to
 * identify which client context to operate on. This interface
 * internally determines the corresponding client context for the
 * given path. The down-side is that a virtual mount point (VMP) needs to be
 * registered with the library. A VMP is just a string that maps to a
 * hadafs_handle_t. The advantage of a VMP based interface is that
 * a user program using multiple client contexts does not need to
 * maintain its own mapping between paths and the corresponding
 * handles.
 */



/* hadafs_mount is the function that allows users to register a VMP
 * along with the parameters, which will be used to initialize a
 * context. Applications calling hadafs_mount do not need to
 * initialized a context using the hadafs_init interface.
 *
 * @vmp         : The virtual mount point.
 * @ipars       : Initialization parameters populated as described
 *              earlier.
 *
 * Returns 0 on success, and -1 on failure.
 */
int
hadafs_mount_old (char *vmp, hadafs_init_params_t *ipars);

int
hadafs_mount ();

/* hadafs_umount is the VMP equivalent of hadafs_fini.
 *
 * @vmp         : The VMP which was initialized using hadafs_mount.
 *
 * Returns 0 on sucess, and -1 on failure.
 */
int
hadafs_umount ();


/* hadafs_umount_all unmounts all the mounts */
int
hadafs_umount_all (void);



/* Opens a file. Corresponds to the open syscall.
 *
 * @handle      : Handle returned from hadafs_init
 * @path        : Path to the file or directory on the hadafs
 *              export. Must be absolute to the export on the server.
 * @flags       : flags to control open behaviour.
 * @...         : The mode_t argument that defines the mode for a new
 *              file, in case a new file is being created using the
 *              O_CREAT flag in @flags.
 *
 * Returns a non-NULL handle on success. NULL on failure and sets
 * errno accordingly.
 */
hadafs_file_t
hadafs_glh_open (hadafs_handle_t handle, char *vmp, const char *path, int flags,
                        ...);


/* Opens a file without having to specify a handle.
 *
 * @path        : Path to the file to open in the hadafs export.
 *              The path to the file in hadafs export must be
 *              pre-fixed with the VMP string registered with
 *              hadafs_mount.
 * @flags       : flags to control open behaviour.
 * @...         : The mode_t argument that defines the mode for a new
 *              file, in case a new file is being created using the
 *              O_CREAT flag in @flags.
 *
 * Returns 0 on success, -1 on failure with errno set accordingly.
 */
hadafs_file_t
hadafs_open (const char *path, int flags, ...);



/* Creates a file. Corresponds to the creat syscall.
 *
 * @handle      : Handle returned from hadafs_init
 * @path        : Path to the file that needs to be created in the
 *              hadafs export.
 * @mode        : File creation mode.
 *
 * Returns the file handle on success. NULL on error with errno set as
 * required.
 */
hadafs_file_t
hadafs_glh_creat (hadafs_handle_t handle, const char *path, mode_t mode);


/* Flush the file identified by the handle.
 *
 * @fd          : Closes the file.
 *
 * Returns 0 on success, -1 on error with errno set accordingly.
 */
int
hadafs_flush (hadafs_file_t fd);

/* Ioctl the file identified by the handle.
 *
 * @fd          : Closes the file.
 * @cmd		: ioctl command
 * @arg		: ioctl argument structure
 *
 * Returns 0 on success, -1 on error with errno set accordingly.
 */
int
hadafs_ioctl (hadafs_file_t fd, uint32_t cmd, uint64_t arg);

/* Close the file identified by the handle.
 *
 * @fd          : Closes the file.
 *
 * Returns 0 on success, -1 on error with errno set accordingly.
 */
int
hadafs_close (hadafs_file_t fd);



/* Read data from a file.
 * @fd          : Handle returned by hadafs_open or
 *              hadafs_glh_open.
 * @buf         : Buffer to read the data into.
 * @nbytes      : Number of bytes to read.
 *
 * Returns number of bytes actually read on success or -1 on error
 * with errno set to the appropriate error number.
 */
ssize_t
hadafs_read (hadafs_file_t fd, void *buf, size_t nbytes);



/* Read data into an array of buffers.
 *
 * @fd          : File handle returned by hadafs_open or
 *              hadafs_glh_open.
 * @vec         : Array of buffers into which the data is read.
 * @count       : Number of iovecs referred to by vec.
 *
 * Returns number of bytes read on success or -1 on error with errno
 * set appropriately.
 */
ssize_t
hadafs_readv (hadafs_file_t fd, const struct iovec *vec, int count);


/* Write data into a file.
 *
 * @fd          : File handle returned from hadafs_open or
 *              hadafs_glh_open.
 * @buf         : Buffer which is written to the file.
 * @nbytes      : Number bytes of the @buf written to the file.
 *
 * On success, returns number of bytes written. On error, returns -1
 * with errno set appropriately.
 */
ssize_t
hadafs_write (hadafs_file_t fd, const void *buf, size_t nbytes);



/* Writes an array of buffers into a file.
 *
 * @fd          : The file handle returned from hadafs_open or
 *              hadafs_glh_open.
 * @vector      : Array of buffers to be written to the file.
 * @count       : Number of separate buffers in the @vector array.
 *
 * Returns number of bytes written on success or -1 on error with
 * errno set approriately.
 */
ssize_t
hadafs_writev (hadafs_file_t fd, const struct iovec *vector, int count);

/* Unlink a file.
 *
 * @handle      : Handle that identifies a hadafs instance.
 * @path        : Path in the hadafs instance that needs to be
 *              unlinked.
 *
 * Returns 0 on success and -1 on error with errno set appropriately.
 */
int
hadafs_glh_unlink (hadafs_handle_t handle, const char *path);


/* Unlink a file.
 *
 * @path        : Path in the hadafs instance that needs to be
 *              unlinked.
 *
 * Returns 0 on success and -1 on error with errno set appropriately.
 */
int
hadafs_unlink (const char *path);

/* FIXME: review the need for these apis */
/* added for log related initialization in booster fork implementation */
void
hadafs_reset (void);

void
hadafs_log_lock (void);

void
hadafs_log_unlock (void);

__END_DECLS

#endif /* !_LIBHADAFSCLIENT_H */
