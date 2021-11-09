/*
   Copyright (c) 2006-2009 HADA, Inc. <http://www.hada.com>
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

/* libhadafs/src/defaults.h:
       This file contains definition of default fops and mops functions.
*/

#ifndef _DEFAULTS_H
#define _DEFAULTS_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "xlator.h"

/* Management Operations */

int32_t default_stats (call_frame_t *frame,
		       xlator_t *this,
		       int32_t flags);

int32_t default_getspec (call_frame_t *frame,
			 xlator_t *this,
			 const char *key,
			 int32_t flag);

int32_t default_checksum (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  int32_t flag);


/* FileSystem operations */
int32_t default_unlink (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc);

int32_t default_stat (call_frame_t *frame,
                        xlator_t *this,
                        loc_t *loc);

int32_t default_fstat (call_frame_t *frame,
                        xlator_t *this,
                        fd_t *fd);

int32_t default_open (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc,
			int32_t flags,
			mode_t mode, fd_t *fd);

int32_t default_readv (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd,
		       size_t size,
		       off_t offset);

int32_t default_writev (call_frame_t *frame,
			xlator_t *this,
			fd_t *fd,
			struct iovec *vector,
			int32_t count,
			off_t offset,
                        struct iobref *iobref);

int32_t default_flush (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd);

int32_t default_ioctl (call_frame_t *frame,
			xlator_t *this,
			fd_t *fd,
			uint32_t cmd,
			uint64_t arg);

int32_t default_truncate (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  off_t offset);

int32_t default_ftruncate (call_frame_t *frame,
			   xlator_t *this,
			   fd_t *fd,
			   off_t offset);

int32_t default_notify (xlator_t *this,
			int32_t event,
			void *data,
			...);

int32_t default_forget (xlator_t *this,
			object_t *object);

int32_t default_release (xlator_t *this,
			 fd_t *fd);

#endif /* _DEFAULTS_H */
