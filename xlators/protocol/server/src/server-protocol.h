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

#ifndef _SERVER_PROTOCOL_H_
#define _SERVER_PROTOCOL_H_

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <pthread.h>

#include "hadafs.h"
#include "xlator.h"
#include "logging.h"
#include "call-stub.h"
#include "authenticate.h"
#include "fd.h"
#include "byte-order.h"
#include "object.h"
#include "name-server.h"

#define DIR_NUM 		   32
#define DEFAULT_BLOCK_SIZE         4194304   /* 4MB */
#define DEFAULT_VOLUME_FILE_PATH   CONFDIR "/hadafs.vol"
#define OBJECT_LRU_LIMIT(this) \
	(((server_conf_t *)(this->private))->object_lru_limit)
#define GET_STATUS_BIT(mode) (int32_t)((mode>>16) & 0x1)
#define SET_STATUS_BIT_O(mode) (int32_t)((mode) | 0x10000)
#define SET_STATUS_BIT_C(mode) (int32_t)((mode) & 0xEFFFF)

typedef struct _server_state server_state_t;

struct server_update_worker_arg;
struct _locker {
	struct list_head  lockers;
        char             *volume;
	loc_t             loc;
	fd_t             *fd;
	pid_t             pid;
};

struct _lock_table {
	struct list_head  file_lockers;
	struct list_head  dir_lockers;
	gf_lock_t         lock;
	size_t            count;
};


/* private structure per connection (transport object)
 * used as transport_t->xl_private
 */
struct _server_connection {
	struct list_head    list;
	char               *id;
	int                 ref;
        int                 active_transports;
	pthread_mutex_t     lock;
	char                disconnected;
	fdtable_t          *fdtable; 
	xlator_t           *bound_xl;
};

typedef struct _server_connection server_connection_t;

typedef int (*server_resume_fn_t) (call_frame_t *frame, xlator_t *bound_xl);

server_connection_t *
server_connection_get (xlator_t *this, const char *id);

void
server_connection_put (xlator_t *this, server_connection_t *conn);

int
server_connection_destroy (xlator_t *this, server_connection_t *conn);

int
server_connection_cleanup (xlator_t *this, server_connection_t *conn);

int
server_nop_cbk (call_frame_t *frame, void *cookie,
		xlator_t *this, int32_t op_ret, int32_t op_errno);


struct _volfile_ctx {
        struct _volfile_ctx *next;
        char                *key;
        uint32_t             checksum;
};

typedef struct {
        struct _volfile_ctx *volfile;

	dict_t           *auth_modules;
	transport_t      *trans;
	int32_t           max_block_size;
	int32_t           object_lru_limit;
	pthread_mutex_t   mutex;
	struct list_head  conns;
        gf_boolean_t      verify_volfile_checksum;
	char		  *local_address;

	//chenxi 20160225
	rd_context_t *rdc;

	//yut20181226
	struct server_update_worker_arg *update_worker;

} server_conf_t;


//yut20181226
#ifndef YUT201812

typedef enum {
	FD_NEWOPEN,
	FD_DIRTY,
	FD_CLEAN,
	FD_RELEASE,
	FD_UNLINK,
	FD_CLOSED
}server_fd_state_t;


typedef struct server_obj{
	struct list_head meta_list;
	struct list_head update_list;
	object_t *object; /* can not be null */
	server_fd_state_t fdstat;
} server_obj_t;

struct server_update_worker_arg{
	//server_conf_t *ser_conf;
	//20190219
	xlator_t *xlator;
	//call_frame_t *frame;
	pthread_t thread;
	pthread_cond_t cond;
	rd_context_t *urdc;
	gf_lock_t lock;
	uint32_t obj_count;
	struct list_head openobjs;
};

#endif

typedef enum {
        RESOLVE_OBJECT = 1,
        RESOLVE_FD,
        RESOLVE_ALL, /*resolve both fd and object */
        RESOLVE_NOT
} server_resolve_type_t;

typedef struct {
        server_resolve_type_t  type;
        uint64_t               fd_no;
        char                  *path;
        char                  *sid;
        uint32_t               soffset;
	char                  *resolved;
        int                    op_ret;
        int                    op_errno;
        loc_t                  deep_loc;
        int                    comp_count;
	/* set close flag for release operation */
	int		       set_close; 
} server_resolve_t;

struct _server_state {
	transport_t      *trans;
	xlator_t         *bound_xl;
	server_resume_fn_t resume_fn;
	loc_t             loc;
	int               flags;
	fd_t             *fd;
	size_t            size;
	off_t             offset;
	mode_t            mode;
	dev_t             dev;
	uid_t             uid;
	gid_t             gid;
	size_t            nr_count;
	int               type;
	object_table_t    *otable;
	int64_t 	  fd_no;
	uint64_t 	  ono;
	char            *path;
	char            *sid;
	char 		*vmp;
	uint32_t        soffset;
	int               mask;
	char              is_revalidate;
	struct timespec   tv[2];
	server_resolve_t  resolve;
        struct iobuf     *iobuf;
        struct iobref    *iobref;
        const char       *volume;
	/* ioctl */
	uint32_t 	cmd;
	uint64_t 	arg;
};

int
resolve_and_resume (call_frame_t *frame, server_resume_fn_t fn);


#endif
