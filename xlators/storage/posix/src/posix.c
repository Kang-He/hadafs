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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#define __XOPEN_SOURCE 500

#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <libgen.h>
#include <ftw.h>

#ifndef GF_BSD_HOST_OS
#include <alloca.h>
#endif /* GF_BSD_HOST_OS */

#include "hadafs.h"
#include "dict.h"
#include "logging.h"
#include "posix.h"
#include "xlator.h"
#include "defaults.h"
#include "common-utils.h"
#include "compat-errno.h"
#include "compat.h"
#include "byte-order.h"
#include "syscall.h"

#undef HAVE_SET_FSID
#ifdef HAVE_SET_FSID

#define DECLARE_OLD_FS_ID_VAR uid_t old_fsuid; gid_t old_fsgid;

#define SET_FS_ID(uid, gid) do {		\
	old_fsuid = setfsuid (uid);     \
	old_fsgid = setfsgid (gid);     \
} while (0)

#define SET_TO_OLD_FS_ID() do {			\
	setfsuid (old_fsuid);           \
	setfsgid (old_fsgid);           \
} while (0)

#else

#define DECLARE_OLD_FS_ID_VAR
#define SET_FS_ID(uid, gid)
#define SET_TO_OLD_FS_ID()

#endif

xlator_t *            THIS = NULL;

#ifndef CRC32
static const unsigned long crctab[256] = {
  0x0,
  0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B,
  0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6,
  0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
  0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
  0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F,
  0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A,
  0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
  0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
  0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033,
  0xA4AD16EA, 0xA06C0B5D, 0xD4326D90, 0xD0F37027, 0xDDB056FE,
  0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
  0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4,
  0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077, 0x30476DC0,
  0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5,
  0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
  0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07,
  0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C,
  0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
  0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
  0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B,
  0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698,
  0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D,
  0x94EA7B2A, 0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
  0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
  0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
  0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80,
  0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
  0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A,
  0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629,
  0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C,
  0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
  0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
  0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65,
  0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8,
  0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
  0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2,
  0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71,
  0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74,
  0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
  0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
  0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A,
  0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087,
  0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
  0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D,
  0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679, 0xC1683BCE,
  0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
  0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
  0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
  0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662,
  0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF,
  0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
};

inline
unsigned long crc32(  const void* buffer,
              unsigned long length,
              unsigned long crc)
{
      const unsigned char* cp = (const unsigned char*)buffer;

      while (length--)
        crc = (crc << 8) ^ crctab[((crc >> 24) ^ *(cp++)) & 0xFF];

      return crc;
}

#endif
void
compute_checksum_forward (char *buf, size_t size, uint32_t *checksum)
{
        int  ret = -1;
        char *checksum_buf = NULL;

        checksum_buf = (char *)(checksum);

        for (ret = 0; ret < (size - 4); ret += 4) {
                checksum_buf[0] ^= (buf[ret]);
                checksum_buf[1] ^= (buf[ret + 1] << 1) ;
                checksum_buf[2] ^= (buf[ret + 2] << 2);
                checksum_buf[3] ^= (buf[ret + 3] << 3);
        }

        for (ret = 0; ret <= (size % 4); ret++) {
                checksum_buf[ret] ^= (buf[(size - 4) + ret] << ret);
        }
        
        return;
}

uint32_t
iov_checksum (const struct iovec *vector, int count)
{
        int i;
        uint32_t checksum=0;

        for (i = 0; i < count; i++) {
                compute_checksum_forward(vector[i].iov_base,vector[i].iov_len,&checksum);
        }

        return checksum;
}

	static int
janitor_walker (const char *fpath, const struct stat *sb,
		int typeflag, struct FTW *ftwbuf)
{
	switch (sb->st_mode & S_IFMT) {
		case S_IFREG:
		case S_IFBLK:
		case S_IFLNK:
		case S_IFCHR:
		case S_IFIFO:
		case S_IFSOCK:
			gf_log ("THIS->name", GF_LOG_TRACE,
					"unlinking %s", fpath);
			unlink (fpath);
			break;

		case S_IFDIR:
			if (ftwbuf->level) { /* don't remove top level dir */
				gf_log ("THIS->name", GF_LOG_TRACE,
						"removing directory %s", fpath);

				rmdir (fpath);
			}
			break;
	}

	return FTW_CONTINUE;

}

	static struct posix_fd *
janitor_get_next_fd (xlator_t *this)
{
	struct posix_private *priv = NULL;
	struct posix_fd *pfd = NULL;

	struct timespec timeout;

	priv = this->private;

	pthread_mutex_lock (&priv->janitor_lock);
	{
		if (list_empty (&priv->janitor_fds)) {
			time (&timeout.tv_sec);
			timeout.tv_sec += priv->janitor_sleep_duration;
			timeout.tv_nsec = 0;

			pthread_cond_timedwait (&priv->janitor_cond,
					&priv->janitor_lock,
					&timeout);
			goto unlock;
		}

		pfd = list_entry (priv->janitor_fds.next, struct posix_fd,
				list);

		list_del (priv->janitor_fds.next);
	}
unlock:
	pthread_mutex_unlock (&priv->janitor_lock);

	return pfd;

}

	static void *
posix_janitor_thread_proc (void *data)
{
	xlator_t *            this = NULL;
	struct posix_private *priv = NULL;
	struct posix_fd *pfd;

	time_t now;

	this = data;
	priv = this->private;

	THIS = this;

	while (1) {
		time (&now);
		if ((now - priv->last_landfill_check) > priv->janitor_sleep_duration) {
			gf_log (this->name, GF_LOG_TRACE,
					"janitor cleaning out /" GF_REPLICATE_TRASH_DIR);

			nftw (priv->trash_path,
					janitor_walker,
					32,
					FTW_DEPTH | FTW_PHYS);

			priv->last_landfill_check = now;
		}

		pfd = janitor_get_next_fd (this);
		if (pfd) {
			gf_log (this->name, GF_LOG_TRACE,
					"janitor: closing file fd=%d", pfd->fd);
			close (pfd->fd);

			if (pfd->path)
				FREE (pfd->path);

			FREE (pfd);
		}
	}

	return NULL;
}


	static void
posix_spawn_janitor_thread (xlator_t *this)
{
	struct posix_private *priv = NULL;
	int ret = 0;

	priv = this->private;

	LOCK (&priv->lock);
	{
		if (!priv->janitor_present) {
			ret = pthread_create (&priv->janitor, NULL,
					posix_janitor_thread_proc, this);

			if (ret < 0) {
				gf_log (this->name, GF_LOG_ERROR,
						"spawning janitor thread failed: %s",
						strerror (errno));
				goto unlock;
			}

			priv->janitor_present = _gf_true;
		}
	}
unlock:
	UNLOCK (&priv->lock);
}


	int
posix_forget (xlator_t *this, object_t *object)
{

	return 0;
}

	int32_t
posix_unlink (call_frame_t *frame, xlator_t *this,
		loc_t *loc)
{
	int32_t                  op_ret    = -1;
	int32_t                  op_errno  = 0;
	char                    *real_path = NULL;
	struct posix_private    *priv      = NULL;

	DECLARE_OLD_FS_ID_VAR;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (loc, out);

	SET_FS_ID (frame->root->uid, frame->root->gid);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	MAKE_REAL_PATH (real_path, this, loc->object->ppath);


	op_ret = unlink (real_path);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"unlink of %s failed: %s", loc->path, 
				strerror (op_errno));
		goto out;
	}

	op_ret = 0;

out:

	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

	int32_t
posix_fstat (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd)
{
	int                  	 _fd      = -1;
	int32_t               	op_ret   = -1;
	int32_t               	op_errno = 0;
	struct stat          buf      = {0,};
	struct posix_fd    *pfd      = NULL;
	uint64_t              	tmp_pfd  = 0;
	int                   	ret      = -1;
	struct posix_private *priv     = NULL; 

	DECLARE_OLD_FS_ID_VAR;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	ret = fd_ctx_get (fd, this, &tmp_pfd);
	if (ret < 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"pfd is NULL, fd=%p", fd);
		op_errno = -ret;
		goto out;
	}
	pfd = (struct posix_fd *)(long)tmp_pfd;

	_fd = pfd->fd;

	op_ret = fstat (_fd, &buf);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR, "fstat failed on fd=%p: %s",
				fd, strerror (op_errno));
		goto out;
	}

	op_ret = 0;

out:

	STACK_UNWIND(frame, op_ret, op_errno, &buf);
	return 0;

}

int32_t
posix_ftruncate (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, off_t offset)
{
        int32_t               op_ret   = -1;
        int32_t               op_errno = 0;
        int                   _fd      = -1;
        struct stat           postop   = {0,};
        struct posix_fd      *pfd      = NULL;
        int                   ret      = -1;
	uint64_t              tmp_pfd  = 0;
        struct posix_private *priv     = NULL;


        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

        ret = fd_ctx_get (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }
	pfd = (struct posix_fd *)(long)tmp_pfd;

        _fd = pfd->fd;

        op_ret = ftruncate (_fd, offset);

        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, 
                        "ftruncate failed on fd=%p: %s",
                        fd, strerror (errno));
                goto out;
        }

        op_ret = fstat (_fd, &postop);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "post-operation fstat failed on fd=%p: %s",
                        fd, strerror (errno));
                goto out;
        }

        op_ret = 0;

 out:

        STACK_UNWIND (frame, op_ret, op_errno, &postop);

        return 0;
}

int32_t
posix_truncate (call_frame_t *frame,
                xlator_t *this,
                loc_t *loc,
                off_t offset)
{
        int32_t               op_ret    = -1;
        int32_t               op_errno  = 0;
        char                 *real_path = 0;
        struct posix_private *priv      = NULL;
        struct stat           postbuf   = {0,};


        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (loc, out);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, out);

		MAKE_REAL_PATH (real_path, this, loc->object->ppath);	

        op_ret = truncate (real_path, offset);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR,
                        "truncate on %s failed: %s",
                        loc->object->ppath, strerror (op_errno));
                goto out;
        }

        op_ret = lstat (real_path, &postbuf);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "lstat on %s failed: %s",
                        real_path, strerror (op_errno));
                goto out;
        }

        op_ret = 0;

 out:

        STACK_UNWIND (frame, op_ret, op_errno,
                             &postbuf);

        return 0;
}

int32_t
posix_stat (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc)
{
	struct stat           buf       = {0,};
	char *                real_path = NULL;
	int32_t               op_ret    = -1;
	int32_t               op_errno  = 0;
	struct posix_private *priv      = NULL; 

	DECLARE_OLD_FS_ID_VAR;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (loc, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	MAKE_REAL_PATH (real_path, this, loc->object->ppath);	

	op_ret = lstat (real_path, &buf);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"lstat on %s failed: %s", real_path, 
				strerror (op_errno));
		goto out;
	}

	op_ret = 0;

out:
	STACK_UNWIND (frame, op_ret, op_errno, &buf);

	return 0;
}


	int32_t
posix_open (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t flags, mode_t mode,
		fd_t *fd)
{
	int32_t                op_ret      = -1;
	int32_t                op_errno    = 0;
	int32_t                _fd         = -1;
	int                    _flags      = 0;
	char *                 real_path   = NULL;
	struct stat            stbuf       = {0, };
	struct posix_fd *      pfd         = NULL;
	struct posix_private * priv        = NULL;
	char                   was_present = 1;  
	uid_t		       uid         = 0;
	gid_t                  gid         = 0;
	char*		       dir	   = NULL;
	int 		       ret 	   = -1;

	DECLARE_OLD_FS_ID_VAR;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (this->private, out);
	VALIDATE_OR_GOTO (loc, out);
	VALIDATE_OR_GOTO (fd, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	MAKE_REAL_PATH (real_path, this, loc->object->ppath);
	uid = frame->root->uid;
	gid = frame->root->gid;


	_flags = flags;

	if (priv->o_direct)
		_flags |= O_DIRECT;


	if (_flags & O_CREAT) {
		gf_log (this->name, GF_LOG_DEBUG,"real_path %s", real_path);
		_fd = open (real_path, _flags, mode);
	} else {
		_fd = open (real_path, _flags);
	}

	if (_fd == -1) {
		op_ret = -1;
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"open on %s failed: %s", loc->path,
				strerror (op_errno));
		goto out;
	}
	else
		gf_log (this->name, GF_LOG_DEBUG,
				"open on %s ok! ", real_path);

	op_ret = fstat (_fd, &stbuf);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"fstat on %d failed: %s", _fd, strerror (op_errno));
		goto out;
	}

	if (!priv->span_devices) {
		if (priv->st_device[0] != stbuf.st_dev) {
			op_errno = EPERM;
			gf_log (this->name, GF_LOG_ERROR,
					"%s: different mountpoint/device, returning "
					"EPERM", loc->path);
			goto out;
		}
	}

	op_ret = -1;
	pfd = CALLOC (1, sizeof (*pfd));

	if (!pfd) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory.");
		goto out;
	}

	pfd->flags = _flags;
	pfd->fd    = _fd;

	fd_ctx_set (fd, this, (uint64_t)(long)pfd);
	/*TODO: check if file exist, if file exist, chown could be ingored */
	op_ret = chown (real_path, uid, gid);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"chown on %s failed: %s",
				real_path, strerror (op_errno));
		goto out;
	}

	LOCK(&priv->lock);
	{
		priv->stats.nr_files++;
	}
	UNLOCK(&priv->lock);

	op_ret = 0;
out:

	if ((-1 == op_ret) && (_fd != -1)) {
		close (_fd);
		if (!was_present) {
			unlink (real_path);
		}
	}

	STACK_UNWIND (frame, op_ret, op_errno, fd, loc->object, &stbuf);

	return 0;
}

#define ALIGN_BUF(ptr,bound) ((void *)((unsigned long)(ptr + bound - 1) & \
			(unsigned long)(~(bound - 1))))

	int
posix_readv (call_frame_t *frame, xlator_t *this,
		fd_t *fd, size_t size, off_t offset)
{
	uint64_t               tmp_pfd    = 0;
	int32_t                op_ret     = -1;
	int32_t                op_errno   = 0;
	int                    _fd        = -1;
	struct posix_private * priv       = NULL;
	struct iobuf         * iobuf      = NULL;
	struct iobref        * iobref     = NULL;
	struct iovec           vec        = {0,};
	struct posix_fd *      pfd        = NULL;
	struct stat            stbuf      = {0,};
	int                    align      = 1;
	int                    ret        = -1;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);
	VALIDATE_OR_GOTO (this->private, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	ret = fd_ctx_get (fd, this, &tmp_pfd);
	if (ret < 0) {
		op_errno = -ret;
		gf_log (this->name, GF_LOG_DEBUG,
				"pfd is NULL from fd=%p", fd);
		goto out;
	}
	pfd = (struct posix_fd *)(long)tmp_pfd;

	if (!size) {
		op_errno = EINVAL;
		gf_log (this->name, GF_LOG_DEBUG, "size=%"GF_PRI_SIZET, size);
		goto out;
	}

	if (pfd->flags & O_DIRECT) {
		align = 4096;    /* align to page boundary */
	}

	iobuf = iobuf_get (this->ctx->iobuf_pool);
	if (!iobuf) {
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory.");
		goto out;
	}

	_fd = pfd->fd;
#ifdef PREAD
	op_ret = lseek (_fd, offset, SEEK_SET);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"lseek(%"PRId64") failed: %s",
				offset, strerror (op_errno));
		goto out;
	}

	op_ret = read (_fd, iobuf->ptr, size);
#else
	op_ret = pread (_fd, iobuf->ptr, size, offset);
#endif
	//gf_log("xiaow612", GF_LOG_NORMAL, "read file %s:%d, offset is %ld, size is %ld", fd->object->path, op_ret, offset, size);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"read failed on fd=%p: %s", fd,
				strerror (op_errno));
		goto out;
	}

	LOCK (&priv->lock);
	{
		priv->read_value    += op_ret;
		priv->interval_read += op_ret;
	}
	UNLOCK (&priv->lock);

	vec.iov_base = iobuf->ptr;
	vec.iov_len  = op_ret;

	op_ret = -1;
	iobref = iobref_new ();

	iobref_add (iobref, iobuf);

	/*
	 *  readv successful, and we need to get the stat of the file
	 *  we read from
	 */

	op_ret = fstat(_fd, &stbuf);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"fstat failed on fd=%p: %s", fd,
				strerror (op_errno));
		goto out;
	}

	op_ret = vec.iov_len;

out:
	STACK_UNWIND (frame, op_ret, op_errno,&vec, 1, &stbuf, iobref);

	if (iobref)
		iobref_unref (iobref);
	if (iobuf)
		iobuf_unref (iobuf);

	return 0;
}


	int32_t
posix_writev (call_frame_t *frame, xlator_t *this,
		fd_t *fd, struct iovec *vector, int32_t count, off_t offset,
		struct iobref *iobref)
{
	int32_t                op_ret   = -1;
	int32_t                op_errno = 0;
	int                    _fd      = -1;
	struct posix_private * priv     = NULL;
	struct posix_fd *      pfd      = NULL;
	struct stat            stbuf    = {0,};
	int                      ret      = -1;

	int    idx          = 0;
	//int    align        = 4096;
	int    align        = 8192;
	int    max_buf_size = 0;
	int    retval       = 0;
	char * buf          = NULL;
	char * alloc_buf    = NULL;
	uint64_t  tmp_pfd   = 0;

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);
	VALIDATE_OR_GOTO (vector, out);
	VALIDATE_OR_GOTO (this->private, out);

	priv = this->private;

	VALIDATE_OR_GOTO (priv, out);

	//chenxi 20160217
	ret = fd_ctx_get (fd, this, &tmp_pfd);
	if (ret < 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"pfd is NULL from fd=%p", fd);
		op_errno = -ret;
		goto out;
	}
	pfd = (struct posix_fd *)(long)tmp_pfd;

	_fd = pfd->fd;
#ifdef PWRITEV
	op_ret = lseek (_fd, offset, SEEK_SET);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR,
				"lseek(%"PRId64") on fd=%p failed: %s",
				offset, fd, strerror (op_errno));
		goto out;
	}
#endif

#ifdef XIAOW20190806
	/* Check for the O_DIRECT flag during open() */
	if (pfd->flags & O_DIRECT) {	/* This is O_DIRECT'd file */
		
		for (idx = 0; idx < count; idx++) {
			if (max_buf_size < vector[idx].iov_len)
				max_buf_size = vector[idx].iov_len;
		}


		alloc_buf = MALLOC (1 * (max_buf_size + align));
		if (!alloc_buf) {
			op_ret = -errno;
			goto out;
		}
		
		op_ret = -1;
		for (idx = 0; idx < count; idx++) {
			/* page aligned buffer */
			buf = ALIGN_BUF (alloc_buf, align);

			memcpy (buf, vector[idx].iov_base,
					vector[idx].iov_len);

			/* not sure whether writev works on O_DIRECT'd fd */
			retval = write (_fd, buf, vector[idx].iov_len);

			if (retval == -1) {
				if (op_ret == -1) {
					op_errno = errno;
					gf_log (this->name, GF_LOG_DEBUG,
							"O_DIRECT enabled on fd=%p: %s",
							fd, strerror (op_errno));
					goto out;
				}

				break;
			}
			if (op_ret == -1)
				op_ret = 0;
			op_ret += retval;
		}


	}else{	/* This is not O_DIRECT'd fd */
#endif
#ifdef PWRITEV
		op_ret = writev (_fd, vector, count);
#else
		op_ret = pwritev (_fd, vector, count, offset);
#endif
		if (op_ret == -1) {
			op_errno = errno;
			gf_log (this->name, GF_LOG_ERROR,
					"writev failed on fd=%p: %s",
					fd, strerror (op_errno));
			goto out;
		}
	//}

	//gf_log("xiaow612", GF_LOG_NORMAL, "file %s, offset is %ld written off is %ld, written  %d:%d, crc32 is %lu", fd->object->path, offset, lseek(_fd, 0, SEEK_CUR), op_ret, vector->iov_base, crc32(vector->iov_base, vector->iov_len, 0));

	LOCK (&priv->lock);
	{
		priv->write_value    += op_ret;
		priv->interval_write += op_ret;
	}
	UNLOCK (&priv->lock);

	if (op_ret >= 0) {
		/* wiretv successful, we also need to get the stat of
		 * the file we wrote to
		 */

		ret = fstat (_fd, &stbuf);
		if (ret == -1) {
			op_ret = -1;
			op_errno = errno;
			gf_log (this->name, GF_LOG_ERROR, 
					" fstat failed on fd=%p: %s",
					fd, strerror (op_errno));
			goto out;
		}
	}


out:

	if (alloc_buf) {
		FREE (alloc_buf);
	}

	STACK_UNWIND (frame, op_ret, op_errno, &stbuf);

	return 0;
}


	int32_t
posix_flush (call_frame_t *frame, xlator_t *this,
		fd_t *fd)
{
	int32_t           	op_ret   = -1;
	int32_t           	op_errno = 0;
	int               		_fd      = -1;
	struct posix_fd * 	pfd      = NULL;
	int               		ret      = -1;
	uint64_t          	tmp_pfd  = 0;
	struct posix_private *priv     = NULL; 
	struct stat          buf      = {0,};

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	ret = fd_ctx_get (fd, this, &tmp_pfd);
	if (ret < 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"pfd is NULL, fd=%p", fd);
		op_errno = -ret;
		goto out;
	}
	pfd = (struct posix_fd *)(long)tmp_pfd;

	_fd = pfd->fd;

	op_ret = fstat (_fd, &buf);
	if (op_ret == -1) {
		op_errno = errno;
		gf_log (this->name, GF_LOG_ERROR, "fstat failed on fd=%p: %s",
				fd, strerror (op_errno));
		goto out;
	}
#ifndef XIAOW
	fsync(_fd);
#endif
	gf_log (this->name, GF_LOG_TRACE, "flush fd %lx, size %ld ctime %ld mtime %ld atime %ld",
			fd, buf.st_size, buf.st_ctime, buf.st_mtime, buf.st_atime);

	op_ret = 0;

out:
	STACK_UNWIND(frame, op_ret, op_errno, &buf);
	return 0;
}


	int32_t
posix_release (xlator_t *this,
		fd_t *fd)
{
	int32_t                op_ret   = -1;
	int32_t                op_errno = 0;
	int                    _fd      = -1;
	struct posix_private * priv     = NULL;
	struct posix_fd *      pfd      = NULL;
	int                    ret      = -1;
	uint64_t               tmp_pfd  = 0;

	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);

	priv = this->private;

	ret = fd_ctx_get (fd, this, &tmp_pfd);
	if (ret < 0) {
		op_errno = -ret;
		gf_log (this->name, GF_LOG_DEBUG,
				"pfd is NULL from fd=%p", fd);
		goto out;
	}
	pfd = (struct posix_fd *)(long)tmp_pfd;

	_fd = pfd->fd;


	gf_log(this->name, GF_LOG_DEBUG, "%s release by posix_xlator", fd->object->path);
	pthread_mutex_lock (&priv->janitor_lock);
	{
		INIT_LIST_HEAD (&pfd->list);
		list_add_tail (&pfd->list, &priv->janitor_fds);
		pthread_cond_signal (&priv->janitor_cond);
	}
	pthread_mutex_unlock (&priv->janitor_lock);

	LOCK(&priv->lock);
	{
		priv->stats.nr_files--;
	}
	UNLOCK(&priv->lock);

out:

	return 0;
}


	int32_t
posix_stats (call_frame_t *frame, xlator_t *this,
		int32_t flags)

{
	int32_t op_ret   = -1;
	int32_t op_errno = 0;

	DECLARE_OLD_FS_ID_VAR;

	SET_FS_ID (frame->root->uid, frame->root->gid);

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);


out:
	SET_TO_OLD_FS_ID ();

	STACK_UNWIND (frame, op_ret, op_errno, NULL);
	return 0;
}

	int32_t
posix_checksum (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t flag)
{

	return 0;
}

	int32_t
posix_ioctl (call_frame_t *frame, xlator_t *this,
		fd_t *fd, uint32_t cmd, uint64_t arg)
{
	int32_t           	op_ret   = 0;
	int32_t           	op_errno = 0;
	int               		_fd      = -1;
	struct posix_fd * 	pfd      = NULL;
	int               		ret      = -1;
	uint64_t          	tmp_pfd  = 0;
	struct posix_private *priv     = NULL; 

	VALIDATE_OR_GOTO (frame, out);
	VALIDATE_OR_GOTO (this, out);
	VALIDATE_OR_GOTO (fd, out);

	priv = this->private;
	VALIDATE_OR_GOTO (priv, out);

	gf_log (this->name, GF_LOG_DEBUG, "CMD %d not implemented", cmd);
out:
	STACK_UNWIND(frame, -1, ENOSYS);
	return 0;

}

/**
 * notify - when parent sends PARENT_UP, send CHILD_UP event from here
 */
	int32_t
notify (xlator_t *this,
		int32_t event,
		void *data,
		...)
{
	switch (event)
	{
		case GF_EVENT_PARENT_UP:
			{
				/* Tell the parent that posix xlator is up */
				default_notify (this, GF_EVENT_CHILD_UP, data);
			}
			break;
		default:
			/* */
			break;
	}
	return 0;
}

/**
 * init -
 */
	int
init (xlator_t *this)
{
	int                    ret      = 0;
	int                    op_ret   = -1;
	gf_boolean_t           tmp_bool = 0;
	struct stat            buf      = {0,};
	struct posix_private * _private = NULL;
	data_t *               dir_data = NULL;
	data_t *               tmp_data = NULL;

	int dict_ret = 0;
	int32_t janitor_sleep;
	int dirnum = 0, i = 0;
	char dir[ZR_PATH_MAX] = "";

	dir_data = dict_get (this->options, "directory");

	if (this->children) {
		gf_log (this->name, GF_LOG_CRITICAL,
				"FATAL: storage/posix cannot have subvolumes");
		ret = -1;
		goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
				"Volume is dangling. Please check the volume file.");
	}

	if (!dir_data) {
		gf_log (this->name, GF_LOG_CRITICAL,
				"Export directory not specified in volume file.");
		ret = -1;
		goto out;
	}

	umask (000); // umask `masking' is done at the client side

	/* Check whether the specified directory exists, if not create it. */
	ret = lstat (dir_data->data, &buf);
	if ((ret != 0) || !S_ISDIR (buf.st_mode)) {
		gf_log (this->name, GF_LOG_ERROR,
				"Directory '%s' doesn't exist, exiting.",
				dir_data->data);
		ret = -1;
		goto out;
	}

	ret = dict_get_int32 (this->options, "dirnum",&dirnum);
	if (ret < 0) {
		gf_log (this->name, GF_LOG_TRACE,"defaulting DIR_NUM to %d",DIR_NUM);
		dirnum = DIR_NUM;
	}
	for(i = 0;i < 32;i++)
	{
		sprintf(dir,"%s/d%d",dir_data->data,i);
		ret = lstat (dir, &buf);
		if ((ret != 0) || !S_ISDIR (buf.st_mode))
		{
			ret = mkdir(dir,0711);
			if(ret < 0)
				gf_log (this->name, GF_LOG_ERROR,"mkdir %s failed",dir);
		}
		memset(dir, 0, ZR_PATH_MAX);
	}

	/* Check for Extended attribute support, if not present, log it */
	op_ret = sys_lsetxattr (dir_data->data,
			"trusted.hadafs.test", "working", 8, 0);
	if (op_ret < 0) {
		tmp_data = dict_get (this->options,
				"mandate-attribute");
		if (tmp_data) {
			if (gf_string2boolean (tmp_data->data,
						&tmp_bool) == -1) {
				gf_log (this->name, GF_LOG_ERROR,
						"wrong option provided for key "
						"\"mandate-xattr\"");
				ret = -1;
				goto out;
			}
			if (!tmp_bool) {
				gf_log (this->name, GF_LOG_WARNING,
						"Extended attribute not supported, "
						"starting as per option");
			} else {
				gf_log (this->name, GF_LOG_CRITICAL,
						"Extended attribute not supported, "
						"exiting.");
				ret = -1;
				goto out;
			}
		} else {
			gf_log (this->name, GF_LOG_CRITICAL,
					"Extended attribute not supported, exiting.");
			ret = -1;
			goto out;
		}
	}

	_private = CALLOC (1, sizeof (*_private));
	if (!_private) {
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory.");
		ret = -1;
		goto out;
	}

	_private->base_path = strdup (dir_data->data);
	_private->base_path_length = strlen (_private->base_path);

	_private->trash_path = CALLOC (1, _private->base_path_length
			+ strlen ("/")
			+ strlen (GF_REPLICATE_TRASH_DIR)
			+ 1);

	if (!_private->trash_path) {
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory.");
		ret = -1;
		goto out;
	}

	strncpy (_private->trash_path, _private->base_path, _private->base_path_length);
	strcat (_private->trash_path, "/" GF_REPLICATE_TRASH_DIR);

	LOCK_INIT (&_private->lock);

	{
		/* Stats related variables */
		gettimeofday (&_private->init_time, NULL);
		gettimeofday (&_private->prev_fetch_time, NULL);
		_private->max_read = 1;
		_private->max_write = 1;
	}

	_private->export_statfs = 1;
	tmp_data = dict_get (this->options, "export-statfs-size");
	if (tmp_data) {
		if (gf_string2boolean (tmp_data->data,
					&_private->export_statfs) == -1) {
			ret = -1;
			gf_log (this->name, GF_LOG_ERROR,
					"'export-statfs-size' takes only boolean "
					"options");
			goto out;
		}
		if (!_private->export_statfs)
			gf_log (this->name, GF_LOG_DEBUG,
					"'statfs()' returns dummy size");
	}

	_private->background_unlink = 0;
	tmp_data = dict_get (this->options, "background-unlink");
	if (tmp_data) {
		if (gf_string2boolean (tmp_data->data,
					&_private->background_unlink) == -1) {
			ret = -1;
			gf_log (this->name, GF_LOG_ERROR,
					"'background-unlink' takes only boolean "
					"options");
			goto out;
		}

		if (_private->background_unlink)
			gf_log (this->name, GF_LOG_DEBUG,
					"unlinks will be performed in background");
	}

	tmp_data = dict_get (this->options, "o-direct");
	if (tmp_data) {
		if (gf_string2boolean (tmp_data->data,
					&_private->o_direct) == -1) {
			ret = -1;
			gf_log (this->name, GF_LOG_ERROR,
					"wrong option provided for 'o-direct'");
			goto out;
		}
		if (_private->o_direct)
			gf_log (this->name, GF_LOG_DEBUG,
					"o-direct mode is enabled (O_DIRECT "
					"for every open)");
	}

	_private->num_devices_to_span = 1;

	tmp_data = dict_get (this->options, "span-devices");
	if (tmp_data) {
		if (gf_string2int32 (tmp_data->data,
					&_private->num_devices_to_span) == -1) {
			ret = -1;
			gf_log (this->name, GF_LOG_ERROR,
					"wrong option provided for 'span-devices'");
			goto out;
		}
		if (_private->num_devices_to_span > 1) {
			gf_log (this->name, GF_LOG_NORMAL,
					"spanning enabled accross %d mounts", 
					_private->num_devices_to_span);
			_private->span_devices = 1;
		}
		if (_private->num_devices_to_span < 1)
			_private->num_devices_to_span = 1;
	}
	_private->st_device = CALLOC (1, (sizeof (dev_t) * 
				_private->num_devices_to_span));

	/* Start with the base */
	_private->st_device[0] = buf.st_dev;

	_private->janitor_sleep_duration = 600;

	dict_ret = dict_get_int32 (this->options, "janitor-sleep-duration",
			&janitor_sleep);
	if (dict_ret == 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"Setting janitor sleep duration to %d.",
				janitor_sleep);

		_private->janitor_sleep_duration = janitor_sleep;
	}

#ifndef GF_DARWIN_HOST_OS
	{
		struct rlimit lim;
		lim.rlim_cur = 1048576;
		lim.rlim_max = 1048576;

		if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
			gf_log (this->name, GF_LOG_WARNING,
					"Failed to set 'ulimit -n "
					" 1048576': %s", strerror(errno));
			lim.rlim_cur = 65536;
			lim.rlim_max = 65536;

			if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
				gf_log (this->name, GF_LOG_WARNING,
						"Failed to set maximum allowed open "
						"file descriptors to 64k: %s", 
						strerror(errno));
			}
			else {
				gf_log (this->name, GF_LOG_NORMAL,
						"Maximum allowed open file descriptors "
						"set to 65536");
			}
		}
	}
#endif

	this->private = (void *)_private;

	pthread_mutex_init (&_private->janitor_lock, NULL);
	pthread_cond_init (&_private->janitor_cond, NULL);
	INIT_LIST_HEAD (&_private->janitor_fds);

	posix_spawn_janitor_thread (this);

out:
	return ret;
}

	void
fini (xlator_t *this)
{
	struct posix_private *priv = this->private;
	sys_lremovexattr (priv->base_path, "trusted.hadafs.test");
	FREE (priv);
	return;
}

struct xlator_mops mops = {
	.stats    = posix_stats,
};

struct xlator_fops fops = {
	.unlink      = posix_unlink,
	.stat        = posix_stat,
	.fstat	     = posix_fstat,
	.open        = posix_open,
	.readv       = posix_readv,
	.writev      = posix_writev,
	.flush       = posix_flush,
	.ioctl 	     = posix_ioctl,
	.checksum    = posix_checksum,
    .truncate    = posix_truncate,
    .ftruncate    = posix_ftruncate
};

struct xlator_cbks cbks = {
	.release     = posix_release,
	.forget      = posix_forget
};

struct volume_options options[] = {
	{ .key  = {"o-direct"},
		.type = GF_OPTION_TYPE_BOOL },
	{ .key  = {"directory"},
		.type = GF_OPTION_TYPE_PATH },
	{ .key  = {"export-statfs-size"},
		.type = GF_OPTION_TYPE_BOOL },
	{ .key  = {"mandate-attribute"},
		.type = GF_OPTION_TYPE_BOOL },
	{ .key  = {"span-devices"},
		.type = GF_OPTION_TYPE_INT },	  
	{ .key  = {"dirnum"},
		.type = GF_OPTION_TYPE_INT },	  
	{ .key  = {"background-unlink"},
		.type = GF_OPTION_TYPE_BOOL },
	{ .key  = {NULL} }
};
