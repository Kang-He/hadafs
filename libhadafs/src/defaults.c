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

/* libhadafs/src/defaults.c:
   This file contains functions, which are used to fill the 'fops' and 'mops'
   structures in the xlator structures, if they are not written. Here, all the
   function calls are plainly forwared to the first child of the xlator, and
   all the *_cbk function does plain STACK_UNWIND of the frame, and returns.

   All the functions are plain enough to understand.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "xlator.h"





static int32_t
default_unlink_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

int32_t
default_unlink (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc)
{
	STACK_WIND (frame,
		    default_unlink_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->unlink,
		    loc);
	return 0;
}


static int32_t
default_open_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
		    fd_t *fd,
		    object_t *object,
		    struct stat *buf)
{
	STACK_UNWIND (frame, op_ret, op_errno, fd, object, buf);
	return 0;
}

int32_t
default_open (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		int32_t flags,
		mode_t mode, fd_t *fd)
{
	STACK_WIND (frame, default_open_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->open,
		    loc, flags, mode, fd);
	return 0;
}


static int32_t
default_readv_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
	           struct stat *stbuf,
                   struct iobref *iobref)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      vector,
		      count,
		      stbuf,
                      iobref);
	return 0;
}

int32_t
default_readv (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd,
	       size_t size,
	       off_t offset)
{
	STACK_WIND (frame,
		    default_readv_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readv,
		    fd,
		    size,
		    offset);
	return 0;
}


static int32_t
default_writev_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
			struct stat *postbuf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      postbuf);
	return 0;
}

int32_t
default_writev (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd,
		struct iovec *vector,
		int32_t count,
		off_t off,
                struct iobref *iobref)
{
	STACK_WIND (frame,
		    default_writev_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->writev,
		    fd,
		    vector,
		    count,
		    off,
                    iobref);
	return 0;
}

static int32_t
default_flush_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
	           struct stat *postbuf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      postbuf);
	return 0;
}

int32_t
default_flush (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd)
{
	STACK_WIND (frame,
		    default_flush_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->flush,
		    fd);
	return 0;
}

static int32_t
default_ioctl_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

int32_t
default_ioctl (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd,
		uint32_t cmd,
		uint64_t arg)
{
	STACK_WIND (frame,
		    default_ioctl_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->ioctl,
		    fd, cmd, arg);
	return 0;
}

static int32_t
default_stat_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  struct stat *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

int32_t
default_stat (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	STACK_WIND (frame,
		    default_stat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->stat,
		    loc);
	return 0;
}

static int32_t
default_truncate_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
			  struct stat *postbuf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
			  postbuf);
	return 0;
}

int32_t
default_truncate (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  off_t offset)
{
	STACK_WIND (frame,
		    default_truncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->truncate,
		    loc,
		    offset);
	return 0;
}

static int32_t
default_ftruncate_cbk (call_frame_t *frame,
		       void *cookie,
		       xlator_t *this,
		       int32_t op_ret,
		       int32_t op_errno,
			   struct stat *postbuf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
			  postbuf);
	return 0;
}

int32_t
default_ftruncate (call_frame_t *frame,
		   xlator_t *this,
		   fd_t *fd,
		   off_t offset)
{
	STACK_WIND (frame,
		    default_ftruncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->ftruncate,
		    fd,
		    offset);
	return 0;
}

int32_t
default_fstat_cbk (call_frame_t *frame,
		void *cookie,
		xlator_t *this,
		int32_t op_ret,
		int32_t op_errno,	
		struct stat *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,		
		      buf);
	return 0;
}
int32_t
default_fstat (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd)
{

	STACK_WIND (frame,
		    default_fstat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fstat,
		    fd);
	return 0;
}

/* Management operations */
static int32_t
default_stats_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct xlator_stats *stats)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      stats);
	return 0;
}


int32_t
default_stats (call_frame_t *frame,
	       xlator_t *this,
	       int32_t flags)
{
	STACK_WIND (frame,
		    default_stats_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->mops->stats,
		    flags);
	return 0;
}

static int32_t
default_getspec_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     char *spec_data)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      spec_data);
	return 0;
}


int32_t
default_getspec (call_frame_t *frame,
		 xlator_t *this,
		 const char *key,
		 int32_t flags)
{
	STACK_WIND (frame,
		    default_getspec_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->mops->getspec,
		    key, flags);
	return 0;
}


static int32_t
default_checksum_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      uint8_t *file_checksum)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      file_checksum);
	return 0;
}


int32_t
default_checksum (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  int32_t flag)
{
	STACK_WIND (frame,
		    default_checksum_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->checksum,
		    loc,
		    flag);
	return 0;
}

/* notify */
int32_t
default_notify (xlator_t *this,
		int32_t event,
		void *data,
		...)
{
	switch (event)
	{
	case GF_EVENT_PARENT_UP:
	{
		xlator_list_t *list = this->children;

		while (list)
		{
			list->xlator->notify (list->xlator, event, this);
			list = list->next;
		}
	}
	break;
	case GF_EVENT_CHILD_DOWN:
	case GF_EVENT_CHILD_UP:
	default:
	{
		xlator_list_t *parent = this->parents;
		while (parent) {
			parent->xlator->notify (parent->xlator, event, this, NULL);
			parent = parent->next;
		}
	}
	}

	return 0;
}

int32_t
default_release (xlator_t *this,
		 fd_t *fd)
{
	return 0;
}

int32_t
default_forget (xlator_t *this,
		object_t *object)
{
	return 0;
}
