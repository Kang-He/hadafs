/*
  Copyright (c) 2006-2009 LW, Inc. <http://www.lw.com>
  This file is part of LWFS.

  LWFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  LWFS is distributed in the hope that it will be useful, but
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

#ifndef _UNIFY_H
#define _UNIFY_H

#include "list.h"
#include "xlator.h"

/* This is used to allocate memory for local structure */
#define INIT_LOCAL(fr, local)                   \
do {                                          \
  local = CALLOC (1, sizeof (unify_local_t));   \
  ERR_ABORT (local);			      \
  if (!local) {                                 \
    STACK_UNWIND (fr, -1, ENOMEM);            \
    return 0;                                 \
  }                                           \
  fr->local = local;                            \
  local->op_ret = -1;                           \
  local->op_errno = ENOENT;                     \
} while (0)

struct unify_private {
	/* Update this structure depending on requirement */
	dict_t *xl_array;
	int16_t child_count;
	int16_t num_child_up;
	char    *child_status;
	uint8_t is_up;
	gf_lock_t lock;
};
typedef struct unify_private unify_private_t;

struct _unify_local_t {
	int32_t op_ret;
	int32_t op_errno;
	mode_t mode;
	off_t offset;
	int32_t flags;
	struct stat stbuf;

	fd_t *fd;
	char *name;
	loc_t loc;
};
typedef struct _unify_local_t unify_local_t;

#endif /* _UNIFY_H */
