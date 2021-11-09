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

#ifndef _CALL_STUB_H_
#define _CALL_STUB_H_

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "xlator.h"
#include "stack.h"
#include "list.h"

typedef struct {
	struct list_head list;
	char wind;
	call_frame_t *frame;
	hadafs_fop_t fop;

	//Qos
	//struct list_head req;
	void* app;
	struct timeval limit_time;
	struct timeval reserve_time;
	int reserve_flag;

	union {
		/* unlink */
		struct {
			fop_unlink_t fn;
			loc_t loc;
		} unlink;
		struct {
			fop_unlink_cbk_t fn;
			int32_t op_ret, op_errno;
		} unlink_cbk;

		/* fstat */
		struct {
			fop_fstat_t fn;
			fd_t *fd;
		} fstat;
		struct {
			fop_fstat_cbk_t fn;
			int32_t op_ret, op_errno;
			struct stat stbuf;
		} fstat_cbk;

        /* truncate */
		struct {
			fop_truncate_t fn;
			loc_t loc;
			off_t off;
		} truncate;
		struct {
			fop_truncate_cbk_t fn;
			int32_t op_ret, op_errno;
            struct stat postbuf;
		} truncate_cbk;
        /* ftruncate */
		struct {
			fop_ftruncate_t fn;
			fd_t *fd;
			off_t off;
		} ftruncate;
		struct {
			fop_ftruncate_cbk_t fn;
			int32_t op_ret, op_errno;
            struct stat postbuf;
		} ftruncate_cbk;
		/* stat */
		struct {
			fop_stat_t fn;
			loc_t loc;
		} stat;
		struct {
			fop_stat_cbk_t fn;
			int32_t op_ret, op_errno;
			struct stat stbuf;
		} stat_cbk;

		/* open */
		struct {
			fop_open_t fn;
			loc_t loc;
			int32_t flags;
			mode_t mode;
			fd_t *fd;
		} open;
		struct {
			fop_open_cbk_t fn;
			int32_t op_ret, op_errno;
			fd_t *fd;
			object_t *object;
			struct stat stbuf;
		} open_cbk;

		/* readv */
		struct {
			fop_readv_t fn;
			fd_t *fd;
			size_t size;
			off_t off;
		} readv;
		struct {
			fop_readv_cbk_t fn;
			int32_t op_ret;
			int32_t op_errno;
			struct iovec *vector;
			int32_t count;
			struct iobref *iobref;
		} readv_cbk;

		/* writev */
		struct {
			fop_writev_t fn;
			fd_t *fd;
			struct iovec *vector;
			int32_t count;
			off_t off;
			struct iobref *iobref;
		} writev;
		struct {
			fop_writev_cbk_t fn;
			int32_t op_ret, op_errno;
		     	struct stat stbuf;
		} writev_cbk;

		/* flush */
		struct {
			fop_flush_t fn;
			fd_t *fd;
		} flush;
		struct {
			fop_flush_cbk_t fn;
			int32_t op_ret, op_errno;
		} flush_cbk;

		/* ioctl */
		struct {
			fop_ioctl_t fn;
			fd_t *fd;
			uint32_t cmd;
			uint64_t arg;
		} ioctl;
		struct {
			fop_ioctl_cbk_t fn;
			int32_t op_ret, op_errno;
		} ioctl_cbk;

		/* checksum */
		struct {
			fop_checksum_t fn;
			loc_t loc;
			int32_t flags;
		} checksum;
		struct {
			fop_checksum_cbk_t fn;
			int32_t op_ret, op_errno;
			uint8_t *file_checksum;
		} checksum_cbk;
	} args;
} call_stub_t;

call_stub_t *
fop_unlink_stub (call_frame_t *frame,
		 fop_unlink_t fn,
		 loc_t *loc);

call_stub_t *
fop_unlink_cbk_stub (call_frame_t *frame,
		     fop_unlink_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno);

call_stub_t *
fop_stat_stub (call_frame_t *frame,
	       fop_stat_t fn,
	       loc_t *loc);
call_stub_t *
fop_stat_cbk_stub (call_frame_t *frame,
		   fop_stat_cbk_t fn,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct stat *buf);

call_stub_t *
fop_truncate_stub (call_frame_t *frame,
		   fop_truncate_t fn,
		   loc_t *loc,
		   off_t off);

call_stub_t *
fop_truncate_cbk_stub (call_frame_t *frame,
		       fop_truncate_cbk_t fn,
		       int32_t op_ret,
			   int32_t op_errno,
			   struct stat *postbuf);

call_stub_t *
fop_ftruncate_stub (call_frame_t *frame,
		    fop_ftruncate_t fn,
		    fd_t *fd,
		    off_t off);

call_stub_t *
fop_ftruncate_cbk_stub (call_frame_t *frame,
			fop_ftruncate_cbk_t fn,
			int32_t op_ret,
			int32_t op_errno,
            struct stat *postbuf);

call_stub_t *
fop_fstat_stub (call_frame_t *frame,
		fop_fstat_t fn,
		fd_t *fd);
call_stub_t *
fop_fstat_cbk_stub (call_frame_t *frame,
		    fop_fstat_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct stat *buf);


call_stub_t *
fop_open_stub (call_frame_t *frame,
		 fop_open_t fn,
		 loc_t *loc,
		 int32_t flags,
		 mode_t mode, fd_t *fd);

call_stub_t *
fop_open_cbk_stub (call_frame_t *frame,
		     fop_open_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno,
		     fd_t *fd,
		     object_t *object,
		     struct stat *buf);

call_stub_t *
fop_readv_stub (call_frame_t *frame,
		fop_readv_t fn,
		fd_t *fd,
		size_t size,
		off_t off);

call_stub_t *
fop_readv_cbk_stub (call_frame_t *frame,
		    fop_readv_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct iovec *vector,
		    int32_t count,
                    struct iobref *iobref);

call_stub_t *
fop_writev_stub (call_frame_t *frame,
		 fop_writev_t fn,
		 fd_t *fd,
		 struct iovec *vector,
		 int32_t count,
		 off_t off,
                 struct iobref *iobref);

call_stub_t *
fop_writev_cbk_stub (call_frame_t *frame,
		     fop_writev_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno,
		     struct stat *stbuf);

call_stub_t *
fop_flush_stub (call_frame_t *frame,
		fop_flush_t fn,
		fd_t *fd);

call_stub_t *
fop_flush_cbk_stub (call_frame_t *frame,
		    fop_flush_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno);

call_stub_t *
fop_ioctl_stub (call_frame_t *frame,
		fop_ioctl_t fn,
		fd_t *fd,
		uint32_t cmd,
		uint64_t arg);

call_stub_t *
fop_ioctl_cbk_stub (call_frame_t *frame,
		    fop_flush_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno);

call_stub_t *
fop_checksum_stub (call_frame_t *frame,
		   fop_checksum_t fn,
		   loc_t *loc,
		   int32_t flags);

call_stub_t *
fop_checksum_cbk_stub (call_frame_t *frame,
		       fop_checksum_cbk_t fn,
		       int32_t op_ret,
		       int32_t op_errno,
		       uint8_t *file_checksum);

void call_resume (call_stub_t *stub);
void call_stub_destroy (call_stub_t *stub);
#endif
