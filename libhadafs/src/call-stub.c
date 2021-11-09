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

#include "call-stub.h"

//QoS
#include <sys/time.h>
#include <time.h>

static call_stub_t *
stub_new (call_frame_t *frame,
	  char wind,
	  hadafs_fop_t fop)
{
	call_stub_t *new = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	new = CALLOC (1, sizeof (*new));
	GF_VALIDATE_OR_GOTO ("call-stub", new, out);

	new->frame = frame;
	new->wind = wind;
	new->fop = fop;

	//QoS
	new->app = NULL;
	gettimeofday(&new->reserve_time, NULL);
	gettimeofday(&new->limit_time, NULL);
	new->reserve_flag = _gf_true;
	//INIT_LIST_HEAD (&new->req);

	INIT_LIST_HEAD (&new->list);
out:
	return new;
}

call_stub_t *
fop_unlink_stub (call_frame_t *frame,
		 fop_unlink_t fn,
		 loc_t *loc)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);
	GF_VALIDATE_OR_GOTO ("call-stub", loc, out);

	stub = stub_new (frame, 1, GF_FOP_UNLINK);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.unlink.fn = fn;
	loc_copy (&stub->args.unlink.loc, loc);
out:
	return stub;
}


call_stub_t *
fop_unlink_cbk_stub (call_frame_t *frame,
		     fop_unlink_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_UNLINK);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.unlink_cbk.fn = fn;
	stub->args.unlink_cbk.op_ret = op_ret;
	stub->args.unlink_cbk.op_errno = op_errno;
out:
	return stub;
}

call_stub_t *
fop_fstat_stub (call_frame_t *frame,
		fop_fstat_t fn,
		fd_t *fd)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 1, GF_FOP_FSTAT);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.fstat.fn = fn;

	if (fd)
		stub->args.fstat.fd = fd_ref (fd);
out:
	return stub;
}

call_stub_t *
fop_truncate_stub (call_frame_t *frame,
		   fop_truncate_t fn,
		   loc_t *loc,
		   off_t off)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);	
	GF_VALIDATE_OR_GOTO ("call-stub", loc, out);

	stub = stub_new (frame, 1, GF_FOP_TRUNCATE);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.truncate.fn = fn;
	loc_copy (&stub->args.truncate.loc, loc);
	stub->args.truncate.off = off;
out:
	return stub;
}

call_stub_t *
fop_truncate_cbk_stub (call_frame_t *frame,
				fop_truncate_cbk_t fn,
				int32_t op_ret,
				int32_t op_errno,
				struct stat *postbuf)
{
		call_stub_t *stub = NULL;

		GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

		stub = stub_new (frame, 0, GF_FOP_TRUNCATE);
		GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

		stub->args.truncate_cbk.fn = fn;
		stub->args.truncate_cbk.op_ret = op_ret;
		stub->args.truncate_cbk.op_errno = op_errno;
		if (postbuf)
				stub->args.truncate_cbk.postbuf = *postbuf;
out:
		return stub;
}

call_stub_t *
fop_fstat_cbk_stub (call_frame_t *frame,
		    fop_fstat_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct stat *buf)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_FSTAT);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.fstat_cbk.fn = fn;
	stub->args.fstat_cbk.op_ret = op_ret;
	stub->args.fstat_cbk.op_errno = op_errno;
	if (buf)
		stub->args.fstat_cbk.stbuf = *buf;
out:
	return stub;
}

call_stub_t *
fop_ftruncate_stub (call_frame_t *frame,
		    fop_ftruncate_t fn,
		    fd_t *fd,
		    off_t off)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 1, GF_FOP_FTRUNCATE);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.ftruncate.fn = fn;
	if (fd)
		stub->args.ftruncate.fd = fd_ref (fd);

	stub->args.ftruncate.off = off;
out:
	return stub;
}

call_stub_t *
fop_ftruncate_cbk_stub (call_frame_t *frame,
			fop_ftruncate_cbk_t fn,
			int32_t op_ret,
			int32_t op_errno,
			struct stat *postbuf)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_FTRUNCATE);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.ftruncate_cbk.fn = fn;
	stub->args.ftruncate_cbk.op_ret = op_ret;
	stub->args.ftruncate_cbk.op_errno = op_errno;
	if (postbuf)
		stub->args.ftruncate_cbk.postbuf = *postbuf;
out:
	return stub;
}

call_stub_t *
fop_stat_stub (call_frame_t *frame,
	       fop_stat_t fn,
	       loc_t *loc)
{
	call_stub_t *stub = NULL;
  
	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);
	GF_VALIDATE_OR_GOTO ("call-stub", loc, out);

	stub = stub_new (frame, 1, GF_FOP_STAT);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.stat.fn = fn;
	loc_copy (&stub->args.stat.loc, loc);
out:
	return stub;
}

call_stub_t *
fop_stat_cbk_stub (call_frame_t *frame,
		   fop_stat_cbk_t fn,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct stat *buf)
{
	call_stub_t *stub = NULL;
	
	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_STAT);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);
	stub->args.stat_cbk.fn = fn;
	stub->args.stat_cbk.op_ret = op_ret;


	stub->args.stat_cbk.op_errno = op_errno;
	if (op_ret == 0)
		stub->args.stat_cbk.stbuf = *buf;
out:
	
	return stub;
}


call_stub_t *
fop_open_stub (call_frame_t *frame,
		 fop_open_t fn,
		 loc_t *loc,
		 int32_t flags,
		 mode_t mode, fd_t *fd)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);
	GF_VALIDATE_OR_GOTO ("call-stub", loc, out);

	stub = stub_new (frame, 1, GF_FOP_OPEN);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.open.fn = fn;
	loc_copy (&stub->args.open.loc, loc);
	stub->args.open.flags = flags;
	stub->args.open.mode = mode;
	if (fd)
		stub->args.open.fd = fd_ref (fd);
out:
	return stub;
}


call_stub_t *
fop_open_cbk_stub (call_frame_t *frame,
		     fop_open_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno,
		     fd_t *fd,
		     object_t *object,
		     struct stat *buf)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_OPEN);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.open_cbk.fn = fn;
	stub->args.open_cbk.op_ret = op_ret;
	stub->args.open_cbk.op_errno = op_errno;
	if (fd)
		stub->args.open_cbk.fd = fd_ref (fd);
	if (object)
		stub->args.open_cbk.object = object_ref (object);
	if (buf)
		stub->args.open_cbk.stbuf = *buf;
out:
	return stub;
}

call_stub_t *
fop_readv_stub (call_frame_t *frame,
		fop_readv_t fn,
		fd_t *fd,
		size_t size,
		off_t off)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 1, GF_FOP_READ);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.readv.fn = fn;
	if (fd)
		stub->args.readv.fd = fd_ref (fd);
	stub->args.readv.size = size;
	stub->args.readv.off = off;
out:
	return stub;
}


call_stub_t *
fop_readv_cbk_stub (call_frame_t *frame,
		    fop_readv_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct iovec *vector,
		    int32_t count,
                    struct iobref *iobref)

{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_READ);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.readv_cbk.fn = fn;
	stub->args.readv_cbk.op_ret = op_ret;
	stub->args.readv_cbk.op_errno = op_errno;
	if (op_ret >= 0) {
		stub->args.readv_cbk.vector = iov_dup (vector, count);
		stub->args.readv_cbk.count = count;
		stub->args.readv_cbk.iobref = iobref_ref (iobref);
	}
out:
	return stub;
}


call_stub_t *
fop_writev_stub (call_frame_t *frame,
		 fop_writev_t fn,
		 fd_t *fd,
		 struct iovec *vector,
		 int32_t count,
		 off_t off,
                 struct iobref *iobref)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);
	GF_VALIDATE_OR_GOTO ("call-stub", vector, out);

	stub = stub_new (frame, 1, GF_FOP_WRITE);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.writev.fn = fn;
	if (fd)
		stub->args.writev.fd = fd_ref (fd);
	stub->args.writev.vector = iov_dup (vector, count);
	stub->args.writev.count = count;
	stub->args.writev.off = off;
        stub->args.writev.iobref = iobref_ref (iobref);
out:
	return stub;
}


call_stub_t *
fop_writev_cbk_stub (call_frame_t *frame,
		     fop_writev_cbk_t fn,
		     int32_t op_ret,
		     int32_t op_errno,
		     struct stat *stbuf)

{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_WRITE);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.writev_cbk.fn = fn;
	stub->args.writev_cbk.op_ret = op_ret;
	stub->args.writev_cbk.op_errno = op_errno;
	if(op_ret > 0)
	     stub->args.writev_cbk.stbuf = *stbuf;
out:
	return stub;
}



call_stub_t *
fop_flush_stub (call_frame_t *frame,
		fop_flush_t fn,
		fd_t *fd)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 1, GF_FOP_FLUSH);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.flush.fn = fn;
	if (fd)
		stub->args.flush.fd = fd_ref (fd);
out:
	return stub;
}


call_stub_t *
fop_flush_cbk_stub (call_frame_t *frame,
		    fop_flush_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno)

{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_FLUSH);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.flush_cbk.fn = fn;
	stub->args.flush_cbk.op_ret = op_ret;
	stub->args.flush_cbk.op_errno = op_errno;
out:
	return stub;
}

call_stub_t *
fop_ioctl_stub (call_frame_t *frame,
		fop_ioctl_t fn,
		fd_t *fd,
		uint32_t cmd,
		uint64_t arg)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 1, GF_FOP_IOCTL);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.ioctl.fn = fn;
	if (fd) {
		stub->args.ioctl.fd = fd_ref (fd);
		stub->args.ioctl.cmd = cmd;
		stub->args.ioctl.arg = arg;
	}
out:
	return stub;
}

call_stub_t *
fop_ioctl_cbk_stub (call_frame_t *frame,
		    fop_ioctl_cbk_t fn,
		    int32_t op_ret,
		    int32_t op_errno)

{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_IOCTL);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.ioctl_cbk.fn = fn;
	stub->args.ioctl_cbk.op_ret = op_ret;
	stub->args.ioctl_cbk.op_errno = op_errno;
out:
	return stub;
}

call_stub_t *
fop_checksum_stub (call_frame_t *frame,
		   fop_checksum_t fn,
		   loc_t *loc,
		   int32_t flags)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);
	GF_VALIDATE_OR_GOTO ("call-stub", loc, out);

	stub = stub_new (frame, 1, GF_FOP_CHECKSUM);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.checksum.fn = fn;
	loc_copy (&stub->args.checksum.loc, loc);
	stub->args.checksum.flags = flags;
out:
	return stub;
}


call_stub_t *
fop_checksum_cbk_stub (call_frame_t *frame,
		       fop_checksum_cbk_t fn,
		       int32_t op_ret,
		       int32_t op_errno,
		       uint8_t *file_checksum)
{
	call_stub_t *stub = NULL;

	GF_VALIDATE_OR_GOTO ("call-stub", frame, out);

	stub = stub_new (frame, 0, GF_FOP_CHECKSUM);
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	stub->args.checksum_cbk.fn = fn;
	stub->args.checksum_cbk.op_ret = op_ret;
	stub->args.checksum_cbk.op_errno = op_errno;
	if (op_ret >= 0)
	{
		stub->args.checksum_cbk.file_checksum = 
			memdup (file_checksum, ZR_FILENAME_MAX);
	}
out:
	return stub;
}


static void
call_resume_wind (call_stub_t *stub)
{
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	switch (stub->fop) {
	case GF_FOP_OPEN:
	{
		stub->args.open.fn (stub->frame,
				      stub->frame->this,
				      &stub->args.open.loc,
				      stub->args.open.flags,
				      stub->args.open.mode,
				      stub->args.open.fd);
		break;
	}
  
  	case GF_FOP_READ:
	{
		stub->args.readv.fn (stub->frame,
				     stub->frame->this,
				     stub->args.readv.fd,
				     stub->args.readv.size,
				     stub->args.readv.off);
		break;
	}

	case GF_FOP_UNLINK:
	{
		stub->args.unlink.fn (stub->frame,
				      stub->frame->this,
				      &stub->args.unlink.loc);
	}
	break;

  
	case GF_FOP_WRITE:
	{
		stub->args.writev.fn (stub->frame,
				      stub->frame->this,
				      stub->args.writev.fd,
				      stub->args.writev.vector,
				      stub->args.writev.count,
				      stub->args.writev.off,
                                      stub->args.writev.iobref);
		break;
	}

	case GF_FOP_STAT:
	{
		stub->args.stat.fn (stub->frame,
				     stub->frame->this,
				     &stub->args.stat.loc);
		break;
	}
	
	case GF_FOP_FLUSH:
	{
		stub->args.flush.fn (stub->frame,
				     stub->frame->this,
				     stub->args.flush.fd);
		break;
	}

	case GF_FOP_IOCTL:
	{
		stub->args.ioctl.fn (stub->frame,
				     stub->frame->this,
				     stub->args.ioctl.fd,
				     stub->args.ioctl.cmd,
				     stub->args.ioctl.arg);
		break;
	}

	case GF_FOP_CHECKSUM:
	{
		stub->args.checksum.fn (stub->frame,
					stub->frame->this,
					&stub->args.checksum.loc,
					stub->args.checksum.flags);
		break;
	}
    
    case GF_FOP_TRUNCATE:
	{
		stub->args.truncate.fn (stub->frame,
					stub->frame->this,
					&stub->args.truncate.loc,
					stub->args.truncate.off);
		break;
	}
    
    case GF_FOP_FTRUNCATE:
	{
		stub->args.ftruncate.fn (stub->frame,
					 stub->frame->this,
					 stub->args.ftruncate.fd,
					 stub->args.ftruncate.off);
		break;
	}

	default:
	{
		gf_log ("call-stub",
			GF_LOG_DEBUG,
			"Invalid value of FOP");
	}
	break;
	}
out:
	return;
}



static void
call_resume_unwind (call_stub_t *stub)
{
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	switch (stub->fop) 
	{
		case GF_FOP_OPEN:
		{
			if (!stub->args.open_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.open_cbk.op_ret,
						stub->args.open_cbk.op_errno,
						stub->args.open_cbk.fd,
						stub->args.open_cbk.object,
						&stub->args.open_cbk.stbuf);
			else
				stub->args.open_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.open_cbk.op_ret,
						stub->args.open_cbk.op_errno,
						stub->args.open_cbk.fd,
						stub->args.open_cbk.object,
						&stub->args.open_cbk.stbuf);

			break;
		}
		case GF_FOP_UNLINK:
		{
			if (!stub->args.unlink_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.unlink_cbk.op_ret,
						stub->args.unlink_cbk.op_errno);
			else
				stub->args.unlink_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.unlink_cbk.op_ret,
						stub->args.unlink_cbk.op_errno);
			break;
		}

		case GF_FOP_STAT:
		{
			if (!stub->args.stat_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.stat_cbk.op_ret,
						stub->args.stat_cbk.op_errno,
						&stub->args.stat_cbk.stbuf);
			else
				stub->args.stat_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.stat_cbk.op_ret,
						stub->args.stat_cbk.op_errno,
						&stub->args.stat_cbk.stbuf);

			break;
		}
		case GF_FOP_READ:
		{
			if (!stub->args.readv_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.readv_cbk.op_ret,
						stub->args.readv_cbk.op_errno,
						stub->args.readv_cbk.vector,
						stub->args.readv_cbk.count,
						stub->args.readv_cbk.iobref);
			else
				stub->args.readv_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.readv_cbk.op_ret,
						stub->args.readv_cbk.op_errno,
						stub->args.readv_cbk.vector,
						stub->args.readv_cbk.count,
						stub->args.readv_cbk.iobref);
			break;
		}
		case GF_FOP_WRITE:
		{
			if (!stub->args.writev_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.writev_cbk.op_ret,
						stub->args.writev_cbk.op_errno,
						&stub->args.writev_cbk.stbuf);
			else
				stub->args.writev_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.writev_cbk.op_ret,
						stub->args.writev_cbk.op_errno,
						&stub->args.writev_cbk.stbuf);
			break;
		}

		case GF_FOP_FLUSH:
		{
			if (!stub->args.flush_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.flush_cbk.op_ret,
						stub->args.flush_cbk.op_errno);
			else
				stub->args.flush_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.flush_cbk.op_ret,
						stub->args.flush_cbk.op_errno);

			break;
		}

		case GF_FOP_FSTAT:
		{
			if (!stub->args.fstat_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.fstat_cbk.op_ret,
						stub->args.fstat_cbk.op_errno,
						&stub->args.fstat_cbk.stbuf);
			else
				stub->args.fstat_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.fstat_cbk.op_ret,
						stub->args.fstat_cbk.op_errno,
						&stub->args.fstat_cbk.stbuf);

			break;
		}

		case GF_FOP_IOCTL:
		{
			if (!stub->args.ioctl_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.ioctl_cbk.op_ret,
						stub->args.ioctl_cbk.op_errno);
			else
				stub->args.ioctl_cbk.fn (stub->frame,
						stub->frame->cookie,
						stub->frame->this,
						stub->args.ioctl_cbk.op_ret,
						stub->args.ioctl_cbk.op_errno);

			break;
		}

		case GF_FOP_CHECKSUM:
		{
			if (!stub->args.checksum_cbk.fn)
				STACK_UNWIND (stub->frame,
						stub->args.checksum_cbk.op_ret,
						stub->args.checksum_cbk.op_errno,
						stub->args.checksum_cbk.file_checksum);
			else
				stub->args.checksum_cbk.fn (stub->frame, 
						stub->frame->cookie,
						stub->frame->this,
						stub->args.checksum_cbk.op_ret, 
						stub->args.checksum_cbk.op_errno,
						stub->args.checksum_cbk.file_checksum);
			if (stub->args.checksum_cbk.op_ret >= 0)
			{
				FREE (stub->args.checksum_cbk.file_checksum);
			}

			break;
		}
        
        case GF_FOP_TRUNCATE:
		{
				if (!stub->args.truncate_cbk.fn)
						STACK_UNWIND (stub->frame,
										stub->args.truncate_cbk.op_ret,
										stub->args.truncate_cbk.op_errno,
										&stub->args.truncate_cbk.postbuf);
				else
						stub->args.truncate_cbk.fn (stub->frame,
										stub->frame->cookie,
										stub->frame->this,
										stub->args.truncate_cbk.op_ret,
										stub->args.truncate_cbk.op_errno,
										&stub->args.truncate_cbk.postbuf);
				break;
		}
        
     	case GF_FOP_FTRUNCATE:
		{
				if (!stub->args.ftruncate_cbk.fn)
						STACK_UNWIND (stub->frame,
										stub->args.ftruncate_cbk.op_ret,
										stub->args.ftruncate_cbk.op_errno,
										&stub->args.ftruncate_cbk.postbuf);
				else
						stub->args.ftruncate_cbk.fn (stub->frame,
										stub->frame->cookie,
										stub->frame->this,
										stub->args.ftruncate_cbk.op_ret,
										stub->args.ftruncate_cbk.op_errno,
										&stub->args.ftruncate_cbk.postbuf);
				break;
		}
		case GF_FOP_MAXVALUE:
		{
			gf_log ("call-stub",
					GF_LOG_DEBUG,
					"Invalid value of FOP");
		}
		break;
	}
out:
	return;
}

static void
call_stub_destroy_wind (call_stub_t *stub)
{
	switch (stub->fop) {
		case GF_FOP_OPEN:
		{
			loc_wipe (&stub->args.open.loc);
			if (stub->args.open.fd)
				fd_unref (stub->args.open.fd);
			break;
		}
		case GF_FOP_UNLINK:
		{
			loc_wipe (&stub->args.unlink.loc);
			break;
		}
		case GF_FOP_STAT:
		{
			loc_wipe (&stub->args.stat.loc);
			break;
		}
		case GF_FOP_READ:
		{
			if (stub->args.readv.fd)
				fd_unref (stub->args.readv.fd);
			break;
		}
		case GF_FOP_WRITE:
		{
			struct iobref *iobref = stub->args.writev.iobref;
			if (stub->args.writev.fd)
				fd_unref (stub->args.writev.fd);
			FREE (stub->args.writev.vector);
			if (iobref)
				iobref_unref (iobref);
			break;
		}
		case GF_FOP_FSTAT:
		{
			if (stub->args.fstat.fd)
				fd_unref (stub->args.fstat.fd);      
			break;
		}
		case GF_FOP_FLUSH:
		{
			if (stub->args.flush.fd)
				fd_unref (stub->args.flush.fd);      
			break;
		}
		case GF_FOP_IOCTL:
		{
			if (stub->args.ioctl.fd)
				fd_unref (stub->args.ioctl.fd);      
			break;
		}
		case GF_FOP_CHECKSUM:
		{
			loc_wipe (&stub->args.checksum.loc);
			break;
		}
		case GF_FOP_TRUNCATE:
		{
				loc_wipe (&stub->args.truncate.loc);
				break;
		}
		case GF_FOP_FTRUNCATE:
		{
				if (stub->args.ftruncate.fd)
						fd_unref (stub->args.ftruncate.fd);
				break;
		}
		case GF_FOP_MAXVALUE:
		{
			gf_log ("call-stub",
					GF_LOG_DEBUG,
					"Invalid value of FOP");
			break;
		}
		default:
			break;
	}
}


static void
call_stub_destroy_unwind (call_stub_t *stub)
{
	switch (stub->fop) 
	{
		case GF_FOP_OPEN:
		{
			if (stub->args.open_cbk.fd) 
				fd_unref (stub->args.open_cbk.fd);

			if (stub->args.open_cbk.object)
				object_unref (stub->args.open_cbk.object);
			break;
		}
		case GF_FOP_UNLINK:
			break;
		case GF_FOP_STAT:
			break;
		case GF_FOP_READ:
		{
			if (stub->args.readv_cbk.op_ret >= 0) {
				struct iobref *iobref = stub->args.readv_cbk.iobref;
				FREE (stub->args.readv_cbk.vector);

				if (iobref) {
					iobref_unref (iobref);
				}
			}
			break;
		}
		case GF_FOP_WRITE:
			break;
		case GF_FOP_FLUSH:
			break;
		case GF_FOP_FSTAT:
			break;
		case GF_FOP_IOCTL:
			break;
		case GF_FOP_CHECKSUM:
		{
			if (stub->args.checksum_cbk.op_ret >= 0) {
				FREE (stub->args.checksum_cbk.file_checksum);
			}
			break;
		}
		case GF_FOP_TRUNCATE:
			break;
		case GF_FOP_FTRUNCATE:
			break;
		case GF_FOP_MAXVALUE:
		{
			gf_log ("call-stub",
				GF_LOG_DEBUG,
				"Invalid value of FOP");
			break;
		}
		default:
			break;
	}
}

void
call_stub_destroy (call_stub_t *stub)
{
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);
	
	if (stub->wind) {
		call_stub_destroy_wind (stub);
	} else {
		call_stub_destroy_unwind (stub);
	}

	FREE (stub);
out:
	return;
}

void
call_resume (call_stub_t *stub)
{
	errno = EINVAL;
	GF_VALIDATE_OR_GOTO ("call-stub", stub, out);

	list_del_init (&stub->list);
	if (stub->wind)
		call_resume_wind (stub);
	else
		call_resume_unwind (stub);

	call_stub_destroy (stub);
out:
	return;
}
