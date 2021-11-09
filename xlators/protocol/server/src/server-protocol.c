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
#include <time.h>
#include <sys/uio.h>
#include <sys/resource.h>

#include <libgen.h>
#include <string.h>

#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "transport.h"
#include "fnmatch.h"
#include "xlator.h"
#include "protocol.h"
#include "server-protocol.h"
#include "server-helpers.h"
#include "call-stub.h"
#include "defaults.h"
#include "list.h"
#include "dict.h"
#include "object.h"
#include "compat.h"
#include "compat-errno.h"
#include "name-server.h"
#include "fd.h"

//#define YUT_META 

char          *nameserver = NULL;
int	      ns_port = -1;



	static void
protocol_server_reply (call_frame_t *frame, int type, int op,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iovec *vector, int count,
		struct iobref *iobref)
{
	server_state_t *state = NULL;
	transport_t    *trans = NULL;
	int             ret = 0;

	state    = CALL_STATE (frame);
	trans    = state->trans;

	hdr->callid = hton64 (frame->root->unique);
	hdr->type   = hton32 (type);
	hdr->op     = hton32 (op);

	ret = transport_submit (trans, (char *)hdr, hdrlen, vector, 
			count, iobref);
	if (ret < 0) {
		gf_log ("protocol/server", GF_LOG_ERROR,
				"frame %"PRId64": failed to submit trans %s op= %d, type= %d",
				frame->root->unique, trans->peerinfo.identifier, op, type);
	}

	STACK_DESTROY (frame->root);

	if (state){
		if(state->fd)
			free_state (state);
	}
}

	static inline void
general_stat (struct stat *stbuf)
{
	/* st arguments owned by hadafs */
	stbuf->st_dev = 314315627;
	stbuf->st_rdev = 0;
	stbuf->st_blksize = 4096;
	stbuf->st_nlink = 0;
	stbuf->st_blocks = stbuf->st_size / 512;
}

/*
 * server_unlink_cbk - unlink callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 *
 * not for external reference
 */
	int
server_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	gf_hdr_common_t      *hdr = NULL;
	gf_fop_unlink_rsp_t  *rsp = NULL;
	server_state_t       *state = NULL;
	size_t                hdrlen = 0;
	int32_t               gf_errno = 0;
	server_conf_t        *conf = NULL;
	server_obj_t         *sobj = NULL;
	uint64_t 	   objaddr = 0;
	rd_context_t	     *rdc = NULL;
	int32_t 	     ret = -1;

	state = CALL_STATE(frame);

	if (op_ret == 0) {
		gf_log (state->bound_xl->name, GF_LOG_TRACE,
				"%"PRId64": UNLINK_CBK %s (%"PRId64")",
				frame->root->unique, state->loc.path,
				state->loc.object->ono);

		/*chenxi20160310: unlink object in NS */
		conf = this->private;
		/* check if this object locate in localhost */
		if(state->loc.object->location == OBJ_LOCALHOST)
		{
			rdc = conf->rdc;
			/*delete success, do not update metadata anymore */
			object_ctx_get(state->loc.object, frame->this, &objaddr);
			sobj = (server_obj_t *)(long)objaddr; 
			if(sobj != NULL) {
				server_update_change_object(sobj->object, this, FD_UNLINK, 1);
				//object_ctx_del(state->loc.object, frame->this, &objaddr);
			}

#ifndef YUTIME
			ret = ns_del_object(rdc,state->loc.object);
#else
			long long t1=0,t2=0;
			t1 = usec();	
			ret = ns_del_object(rdc,state->loc.object);
			t2 = usec();	
			gf_log(this->name,GF_LOG_ERROR,"deleteNS %s in NS use %lld\n",state->loc.path, t2-t1);
#endif
			if(ret < 0)
			{
				gf_log(this->name,GF_LOG_ERROR,"delete %s in NS failed",state->loc.path);
				op_ret = -1;
				op_errno = errno;
			}

		}
		object_unlink (state->loc.object);

	} 
	else {
		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": UNLINK %s (%"PRId64") ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path, 
				state->loc.object ? state->loc.object->ono : 0,
				op_ret, strerror (op_errno));
	}

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_UNLINK,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * server_flush_cbk - flush callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
	int
server_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	gf_hdr_common_t    *hdr = NULL;
	gf_fop_flush_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             gf_errno = 0;
	server_state_t     *state = NULL;
	server_conf_t     *conf = NULL;
	//rd_context_t      *rdc = NULL;
	//object_t		   *object = NULL;

	state = CALL_STATE(frame);
	if (op_ret < 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": FLUSH %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->resolve.fd_no, 
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	} else 
		//yuting
#ifndef YUT_META
	{
		//conf = this->private;
		//struct server_update_worker_arg *worker = conf->update_worker;
		//pthread_cond_signal(&worker->cond);
	} 

#else
	{
		//update object stat
		if( state->fd != NULL)
			object = state->fd->object;
		if(!object)
		{
			gf_log (this->name, GF_LOG_ERROR,
					"Update object stat failed : object is NULL");
			op_ret = -1;
			op_errno = errno;
		}
		else
		{
			if(object->location == OBJ_LOCALHOST)
			{
				object->size = stbuf->st_size;
				object->ctime = stbuf->st_ctime;
				object->mtime = stbuf->st_mtime;
				object->atime = stbuf->st_atime;
				conf = this->private;
				rdc = conf->rdc;

				ret = ns_update_object (rdc, object, UPDATE_SIZE | 
						UPDATE_ATIME | UPDATE_CTIME | UPDATE_MTIME);
				if(ret < 0)
				{
					gf_log (this->name, GF_LOG_ERROR,
							"Update object %s stat to NS failed",
							object->path);
					op_ret = -1;
					op_errno = errno;
				}
			}
		}
	}
#endif

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	if(op_ret >= 0)
		gf_stat_from_stat(&rsp->stat, stbuf);

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_FLUSH,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * server_ioctl_cbk - flush callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
	int
server_ioctl_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	gf_hdr_common_t    *hdr = NULL;
	gf_fop_ioctl_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             gf_errno = 0;
	server_state_t     *state = NULL;

	state = CALL_STATE(frame);
	if (op_ret < 0) {
		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": IOCTL %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->resolve.fd_no, 
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}
	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);


	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_IOCTL,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * server_release_cbk - rleease callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
	int
server_release_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	gf_hdr_common_t      *hdr = NULL;
	gf_cbk_release_rsp_t *rsp = NULL;
	size_t                hdrlen = 0;
	int32_t               gf_errno = 0;

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);


	protocol_server_reply (frame, GF_OP_TYPE_CBK_REPLY, GF_CBK_RELEASE,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * server_writev_cbk - writev callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */

	int
server_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	gf_hdr_common_t    *hdr = NULL;
	gf_fop_write_rsp_t *rsp = NULL;
	server_conf_t      *conf = NULL;
	size_t              hdrlen = 0;
	server_state_t     *state = NULL;
	uint64_t 	   objaddr = 0;
	server_obj_t    *sobj = NULL;

	state = CALL_STATE(frame);
	conf = this->private;

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hdr->rsp.op_errno = hton32 (gf_errno_to_error (op_errno));

	if (op_ret >= 0) {
		gf_stat_from_stat (&rsp->stat, stbuf);
		if(state->fd->object->location == OBJ_LOCALHOST){
			object_ctx_get(state->fd->object, this, &objaddr);
			sobj = (server_obj_t *)(long)objaddr; 
			if(sobj != NULL) {
				server_update_change_object(sobj->object, this, FD_DIRTY, 0);
                        }

		}
	} 
	else {

		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": WRITEV %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->resolve.fd_no, 
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_WRITE,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * server_readv_cbk - readv callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @vector:
 * @count:
 *
 * not for external reference
 */
	int
server_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno,
		struct iovec *vector, int32_t count, struct stat *stbuf, struct iobref *iobref)
{
	gf_hdr_common_t   *hdr = NULL;
	gf_fop_read_rsp_t *rsp = NULL;
	size_t             hdrlen = 0;
	int32_t            gf_errno = 0;
	server_state_t    *state = NULL;

	state = CALL_STATE(frame);
	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);
	if (op_ret >= 0) {
		gf_stat_from_stat (&rsp->stat, stbuf);
	}else{

		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": READV %"PRId64" (%s ==> %"PRId32" (%s)",
				frame->root->unique, state->resolve.fd_no, 
				state->fd != NULL?state->fd->object->path:0, op_ret,
				strerror (op_errno));
	}


	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_READ,
			hdr, hdrlen, vector, count, iobref);

	return 0;
}

/*
 * server_open_cbk - open callback for server
 * @frame: call frame
 * @cookie:
 * @this:  translator structure
 * @op_ret:
 * @op_errno:
 * @fd: file descriptor
 * @object: object structure
 * @stbuf: struct stat of created file
 *
 * not for external reference
 */
	int
server_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno,
		fd_t *fd, object_t *object, struct stat *stbuf)
{
	server_connection_t *conn = NULL;
	gf_hdr_common_t     *hdr = NULL;
	gf_fop_open_rsp_t   *rsp = NULL;
	server_state_t      *state = NULL;
	server_conf_t       *conf = NULL;
	server_obj_t        *sobj = NULL;
	rd_context_t        *rdc = NULL;
	size_t               hdrlen = 0;
	int32_t              gf_errno = 0;

	//long long t1 =0,t2 =0;

	conn = SERVER_CONNECTION (frame);

	state = CALL_STATE (frame);

	if (op_ret >= 0) {
		gf_log (state->bound_xl->name, GF_LOG_TRACE,
				"%"PRId64": OPEN  %s (%"PRId64")",
				frame->root->unique, state->loc.path, stbuf->st_ino);

		object->lno = stbuf->st_ino;
		/* set open flag when open */
		object->mode = SET_STATUS_BIT_O(object->mode);
		object->uid = frame->root->uid;
		object->gid = frame->root->gid;
		object->size = stbuf->st_size;
		object->ctime = stbuf->st_ctime;
		object->mtime = stbuf->st_mtime;
		object->atime = stbuf->st_atime;

		/* chenxi : object_flush to NS */
		int ret = -1;
		conf = this->private;
		rdc = conf->rdc;
		if(state->resolve.op_ret != 0) 
		{
			/* object exist when resolve */
#ifndef YUTIME
			ret = ns_set_object (rdc, object);
#else
			t1=usec();
			ret = ns_set_object (rdc, object);
			t2=usec();
			gf_log (this->name, GF_LOG_ERROR,"AddNS %s to NS use %lld ",object->path, t2-t1);
#endif
			if(ret < 0) 
			{
				gf_log (this->name, GF_LOG_ERROR,"Add %s to NS failed",object->path);
				op_ret = -1;
			}
		} else {
			/* object should be updated in nameserver by its localhost */
			if(object->location == OBJ_LOCALHOST)
			{
#ifndef YUTIME
				ret = ns_update_object (rdc, object, UPDATE_ATIME | UPDATE_SIZE);
#else
				t1=usec();
				ret = ns_update_object (rdc, object, UPDATE_ATIME);
				t2=usec();
				gf_log (this->name, GF_LOG_ERROR,"UpdatNS %s to NS use %lld ",object->path, t2-t1);
#endif

				if(ret < 0) 
				{
					gf_log (this->name, GF_LOG_ERROR,"Update %s to NS failed",object->path);
					op_ret = -1;
					op_errno = errno;
				}
			}
		}

		if(op_ret >= 0){
			state->fd_no = gf_fd_unused_get (conn->fdtable, fd);

#ifndef HEXB20181030
			op_ret = state->fd_no;
			if ((state->fd_no < 0) || (fd == 0)) {
				op_errno = errno;
			}

#else
			if ((state->fd_no < 0) || (fd == 0)) {
				op_ret = state->fd_no;
				op_errno = errno;
			}
#endif
			fd_bind (fd);
			fd_ref(fd);
			gf_log(this->name, GF_LOG_DEBUG, "OPEN %s get nhh fd %d", object->path, op_ret);
		} else
			state->fd_no = -1;
		/* yuting put fd to the update meta process fd_list */
#ifndef YUT_META
		if(object->location == OBJ_LOCALHOST){
			//openfd_t *openfd=new_openfd(fd);;
			sobj = CALLOC (1, sizeof (server_obj_t));
			if(sobj != NULL) {
				sobj->object = object_ref(object); 
				sobj->fdstat = FD_NEWOPEN;
				INIT_LIST_HEAD (&sobj->meta_list);


				if(!object_ctx_put(object, this, (uint64_t)(long)sobj))
					gf_log(this->name, GF_LOG_TRACE,
							"OPEN_CBK object %s state->fd addr %p object %p ctx_object_addr %p:%p",
							state->fd->object->path, state->fd, state->fd->object, sobj,
							sobj->object);
				else
					gf_log (this->name, GF_LOG_ERROR, "ctx put failed!");
				server_update_add_openfd(sobj, conf);
			} else {
				gf_log (this->name, GF_LOG_ERROR, "Out of memory");
			}
		}
#endif

	} else {
		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": OPEN %s (%"PRId64") ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path, 
				state->loc.object ? state->loc.object->ono : 0,
				op_ret, strerror (op_errno));

	}


	//

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);
	rsp->fd           = hton64 (state->fd_no);

#ifdef HEXB20181030
	if(op_ret >= 0)
		gf_stat_from_stat(&rsp->stat, stbuf);
#endif

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_OPEN,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*NOTE: open object need op permission on object. */
#define SERVER_PERMISSION_CHECK(flags, mode, readperm, writeperm, retval)  \
	do {  \
		if( flags & O_RDWR ){   \
			if( (mode & readperm) && (mode & writeperm) ) \
			retval = 0; \
			else \
			retval = -1; \
		}   \
		else if( flags & O_WRONLY ) {	\
			if( mode & writeperm )   \
			retval = 0;   \
			else   \
			retval = -1;   \
		}   \
		else {	\
			if( mode & readperm )   \
			retval = 0;   \
			else   \
			retval = -1;   \
		}   \ 
	} while(0)

/* If stack->uid & stack->gid have the permission(define in flags) needed 
   by this object defined ? */

	int32_t 
server_op_allowed (call_stack_t *stack, int flags, object_t  *object)
{
	int ret = -1;

	if(stack->uid == 0) { // root user
		ret = 0;
		return ret;
	}else if(stack->uid == object->uid) {
		SERVER_PERMISSION_CHECK(flags,object->mode, S_IRUSR, S_IWUSR, ret);
	}else if(stack->gid == object->gid) {
		SERVER_PERMISSION_CHECK(flags, object->mode, S_IRGRP, S_IWGRP, ret);
	}else {
		SERVER_PERMISSION_CHECK(flags, object->mode, S_IROTH, S_IWOTH, ret);
	}

	gf_log("server", GF_LOG_TRACE, "uid:%d, gid:%d, ouid:%d, ogid:%d, mode:%o, flags=%d, ret=%d",
			stack->uid, stack->gid, object->uid, object->gid, object->mode, flags, ret);

	return ret;
}

void get_posix_path(object_t *obj)
{
	int dir_no = (obj->ono)%DIR_NUM;
	int i;
	char *file = strdup(obj->path);
	obj->ppath = calloc(128,sizeof(char));

	for(i = 0;i < strlen(file);i++)
	{
		if(file[i] == '/')
			file[i] = '_';
	}

	sprintf(obj->ppath,"/d%d/%s",dir_no,file);
	free(file);
	return;
}

#if 0
{
	struct update_worker_arg *worker = conf->update_worker;
	if(worker == NULL){	
		gf_log ("server", GF_LOG_ERROR, "worker is NULL\n");
	}else{
		pthread_mutex_lock (&worker->mutex);
		{
			openfd_list_t *myfd= NULL;
			openfd_list_t *tmp= NULL;
			openfd_list_t *tmplist= worker->openfd;
			myfd = calloc(1, sizeof(*myfd));
			myfd->fd = fd_ref(state->fd);
			//myfd->fd = state->fd;
			myfd->fs_st = FD_NEWOPEN;
			INIT_LIST_HEAD (&myfd->fd_list);

			list_add_tail(&myfd->fd_list, &tmplist->fd_list);
			tmplist->fd_count ++;
			gf_log("server", GF_LOG_ERROR, "list_add %lx  list is %lx myfd_count is %d\n", myfd->fd, myfd->fd_list, (tmplist->fd_count));
			list_for_each_entry (tmp, &tmplist->fd_list, fd_list) {
				gf_log("server", GF_LOG_ERROR, "myfd_fd is %lx fd_count  is %d \n", (tmp->fd),tmp->fd_count);
			}
			pthread_cond_signal (&worker->cond);
		}
	}
	UNLOCK (&worker->mutex);


}

#endif

	int
server_open_resume (call_frame_t *frame, xlator_t *bound_xl)
{

	server_state_t *state = NULL;
	xlator_t *this = frame->this;
	server_conf_t *conf = this->private;
	int ret = -1;

	state = CALL_STATE (frame);

	if (state->resolve.op_ret < 0 ){
		if (state->resolve.op_errno == ENOENT){ // create an new object...
			object_hash_compute(state->loc.path,&state->loc.object->ono);
			get_posix_path(state->loc.object);
			state->loc.object->vmp = strdup(state->vmp);
			state->loc.object->lhost = conf->local_address;
			state->loc.object->location = OBJ_LOCALHOST;
			state->loc.object->mode = state->mode;

		}
		else
			goto err;
	}

	if( state->resolve.op_ret == 0 ){  //object is already exist
		ret = server_op_allowed(frame->root, state->flags, state->loc.object);
		if(ret == -1){
			gf_log ("server",
				GF_LOG_ERROR, 
				"server_is_op_allowed returned -1 when open %s,mode %d",
				state->path, state->loc.object->mode);
			state->resolve.op_ret = -1;
			state->resolve.op_errno = EACCES;
			goto err;
		}
	}

	if ( state->resolve.op_ret == 2) {
		/* object parent dir not exist, diff to object not exist */
		state->resolve.op_ret = -1;
		state->resolve.op_errno = ENOENT;
		goto err;
	}

	state->fd = fd_create (state->loc.object, frame->root->pid);
	state->fd->flags = state->flags;


	/*
	 * here we craate file with S_IRUSR|S_IWUSR in local storage.
	 * the real mode is in database
	 */
	STACK_WIND (frame, server_open_cbk,
			bound_xl, bound_xl->fops->open,
			&(state->loc), state->flags, S_IRUSR|S_IWUSR, state->fd);


	return 0;
err:
	server_open_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL, 0, NULL);
	return 0;
}

/*
 * server_open - open function for server
 * @frame: call frame
 * @bound_xl: translator this server is bound to
 * @params: parameters dictionary
 *
 * not for external reference
 */
	int
server_open (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_open_req_t   *req = NULL;
	server_state_t      *state = NULL;
	size_t               pathlen = 0;
	size_t		     sidlen = 0;
	int32_t		    ret = -1;
	//long long t1 =0, t2 =0;

	req   = gf_param (hdr);
	state = CALL_STATE(frame);
	pathlen = STRLEN_0(req->path);

	state->resolve.type  = RESOLVE_OBJECT;
	state->path = req->path;
	state->sid = req->path + pathlen;

	sidlen = STRLEN_0(state->sid);
	state->vmp = req->path + pathlen + sidlen;

	state->soffset = ntoh32 (req->soffset);
	state->mode  = ntoh32 (req->mode);
	state->flags = gf_flags_to_flags (ntoh32 (req->flags));

	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_open_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL, 0, NULL);
		return -1;
	}

#ifndef YUTIME
	resolve_and_resume (frame, server_open_resume);
#else
	t1 = usec();
	resolve_and_resume (frame, server_open_resume);
	t2 = usec();
	gf_log ("YUT", GF_LOG_ERROR,"openresolve NS use %lld ", t2-t1);
#endif

	return 0;
}

	int
server_readv_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t    *state = NULL;

	state = CALL_STATE (frame);

	if (state->resolve.op_ret != 0)
		goto err;

	STACK_WIND (frame, server_readv_cbk,
			bound_xl, bound_xl->fops->readv,
			state->fd, state->size, state->offset);

	return 0;
err:
	server_readv_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL, 0, NULL, NULL);
	return 0;
}
/*
 * server_readv - readv function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_readv (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{

	gf_fop_read_req_t   *req = NULL;
	server_state_t      *state = NULL;

	req = gf_param (hdr);
	state = CALL_STATE (frame);

	state->resolve.type   = RESOLVE_FD;
	state->resolve.fd_no  = ntoh64 (req->fd);
	state->size           = ntoh32 (req->size);
	state->offset         = ntoh64 (req->offset);

	resolve_and_resume (frame, server_readv_resume);

	return 0;

}

	int
server_writev_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t   *state = NULL;
	struct iovec      iov = {0, };

	state = CALL_STATE (frame);

	if (state->resolve.op_ret != 0)
		goto err;

	iov.iov_len  = state->size;

	if (state->iobuf) {
		iov.iov_base = state->iobuf->ptr;
	}

	STACK_WIND (frame, server_writev_cbk,
			bound_xl, bound_xl->fops->writev,
			state->fd, &iov, 1, state->offset, state->iobref);

	return 0;
err:
	server_writev_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL);
	return 0;
}


/*
 * server_writev - writev function for server
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_writev (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_write_req_t  *req = NULL;
	server_state_t      *state = NULL;
	struct iobref       *iobref = NULL;

	req   = gf_param (hdr);
	state = CALL_STATE (frame);

	state->resolve.type  = RESOLVE_FD;
	state->resolve.fd_no = ntoh64 (req->fd);
	state->offset        = ntoh64 (req->offset);
	state->size          = ntoh32 (req->size);

	if (iobuf) {
		iobref = iobref_new ();
		state->iobuf = iobuf;
		iobref_add (iobref, state->iobuf);
		state->iobref = iobref;
	}

	resolve_and_resume (frame, server_writev_resume);

	return 0;
}

/*
 * server_forget_cbk - forget callback for server protocol
 * not for extenal reference
 */
	int
server_forget (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_log ("forget", GF_LOG_CRITICAL, "function not implemented");
	return 0;
}

int
server_release_resume(call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t *state = NULL;
	server_connection_t   *conn = NULL;
	uint64_t objaddr;
	server_obj_t *sobj = NULL;
	server_conf_t *conf = (server_conf_t *)frame->this->private;

	state = CALL_STATE (frame);
	if (state->resolve.op_ret < 0 ){
		gf_log (bound_xl->name, GF_LOG_ERROR, 
				"RESOLVE %p failed: return %d, error %s",
				&state, state->resolve.op_ret, strerror(state->resolve.op_errno));
	} else {
		if(state->fd->object->location == OBJ_LOCALHOST){
			object_ctx_get(state->fd->object, frame->this, &objaddr);
			sobj = (server_obj_t *)(long)objaddr; 
			gf_log(bound_xl->name, GF_LOG_TRACE, "RELEASE object %s sboj, addr %p ctx_object_addr %p:%p",
				state->fd->object->path, state->fd->object, sobj, sobj->object);
			server_update_change_object(sobj->object, frame->this, FD_RELEASE, 0);
			//object_ctx_del(state->fd->object, frame->this, &objaddr);
		}
		
		gf_log (bound_xl->name, GF_LOG_TRACE,
				"RESOLVE %p %s %"PRId64": RELEASE \'fd=%"PRId64"\'", 
				&state, state->fd->object->path, frame->root->unique, state->resolve.fd_no);
	}

	conn = SERVER_CONNECTION(frame);
	gf_fd_put (conn->fdtable, state->resolve.fd_no);

	server_release_cbk (frame, NULL, frame->this, 0, 0);
	return 0;
}

/*
 * server_release - release function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_release (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_cbk_release_req_t  *req = NULL;
	server_state_t        *state = NULL;
	//int32_t              ret = -1;
	req = gf_param (hdr);

	state = CALL_STATE(frame);	
	state->resolve.type  = RESOLVE_FD;
	state->resolve.set_close = 1;
	//state->fd_no = ntoh64 (req->fd);
	state->resolve.fd_no = ntoh64 (req->fd);

#ifndef YUTIME
	resolve_and_resume (frame, server_release_resume);
#else
	long long t1=0, t2=0;
	t1 = usec();
	resolve_and_resume (frame, server_release_resume);
	t2 = usec();
#endif
	return 0;
}

int
server_flush_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t    *state = NULL;

	state = CALL_STATE (frame);

	if (state->resolve.op_ret != 0)
		goto err;

	STACK_WIND (frame, server_flush_cbk,
			bound_xl, bound_xl->fops->flush, state->fd);
	return 0;
err:
	server_flush_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL);

	return 0;
}

/*
 * server_flush - flush function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
int
server_flush (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_flush_req_t *req = NULL;
	server_state_t      *state = NULL;

	req   = gf_param (hdr);
	state = CALL_STATE (frame);

	state->resolve.type  = RESOLVE_FD;
	state->resolve.fd_no = ntoh64 (req->fd);

#ifndef YUTIME
	resolve_and_resume (frame, server_flush_resume);
#else
	long long t1=0, t2=0;
	t1 = usec();
	resolve_and_resume (frame, server_flush_resume);
	t2 = usec();
	gf_log ("YUT", GF_LOG_ERROR,"releaseresolve NS use %lld ", t2-t1);
#endif


	return 0;
}

	int
server_ioctl_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t    *state = NULL;

	state = CALL_STATE (frame);

	if (state->resolve.op_ret != 0)
		goto err;

	STACK_WIND (frame, server_ioctl_cbk,
			bound_xl, bound_xl->fops->ioctl, state->fd, state->cmd, state->arg);
	return 0;
err:
	server_ioctl_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno);

	return 0;
}

/*
 * server_ioctl - ioctl function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */

	int
server_ioctl (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_ioctl_req_t *req = NULL;
	server_state_t      *state = NULL;

	req   = gf_param (hdr);
	state = CALL_STATE (frame);

	state->resolve.type  = RESOLVE_FD;
	state->resolve.fd_no = ntoh64 (req->fd);
	state->cmd = ntoh32(req->cmd);

	/* TODO: add more arguments as needed */
	state->arg = 0;

	resolve_and_resume (frame, server_ioctl_resume);

	return 0;
}

	int
server_unlink_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t *state = NULL;
	int ret = 0;

	state = CALL_STATE(frame);

	if(state->resolve.op_ret < 0)
		goto err;

	/* TODO permission check */
	if( state->resolve.op_ret == 0 ){  //object is already exist
		ret = server_op_allowed(frame->root, state->flags,state->loc.object);
		if(ret == -1){
			gf_log ("server",
				GF_LOG_ERROR, 
				"server_is_op_allowed returned -1 when unlink %s",
				state->path);
			state->resolve.op_ret = -1;
			state->resolve.op_errno = EACCES;
			goto err;
		}
	}

	gf_log (bound_xl->name, GF_LOG_TRACE,
			"%"PRId64": UNLINK %s (%"PRId64")\'", 
			frame->root->unique,  state->path, 
			state->loc.object->ono);

	STACK_WIND (frame, server_unlink_cbk,
			bound_xl,
			bound_xl->fops->unlink,
			&(state->loc));
	return 0;

err:
	server_unlink_cbk(frame, NULL, frame->this,
			state->resolve.op_ret, state->resolve.op_errno);
	return 0;

}

/*
 * server_unlink - unlink function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_unlink (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_unlink_req_t *req = NULL;
	server_state_t      *state = NULL;
	//int32_t              ret = -1;

	req   = gf_param (hdr);
	state = CALL_STATE (frame);

	state->resolve.type  = RESOLVE_OBJECT;
	state->resolve.path   = strdup (req->path);
	state->path = req->path;
	server_loc_fill (&(state->loc), state, state->path);

#ifndef YUTIME
	resolve_and_resume (frame, server_unlink_resume);
#else
	long long t1=0, t2=0;
	t1 = usec();
	resolve_and_resume (frame, server_unlink_resume);
	t2 = usec();
	gf_log ("YUT", GF_LOG_ERROR,"unlinkresolve NS use %lld ", t2-t1);
#endif

	return 0;
}

/*
 * server_fstat_cbk - fstat callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @stbuf:
 *
 */
	int
server_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	gf_hdr_common_t    *hdr = NULL;
	gf_fop_fstat_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             gf_errno = 0;
	server_state_t     *state = NULL;

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	if (op_ret == 0) {
		gf_stat_from_stat (&rsp->stat, stbuf);
	} else {
		state = CALL_STATE(frame);

		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": FSTAT %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->resolve.fd_no,
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_FSTAT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


	int
server_fstat_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t     *state = NULL;

	state = CALL_STATE (frame);
	if(state->resolve.op_ret != 0) //object is not exist , error !!!
		goto err;

	object_t * obj = state->loc.object;
	struct stat stbuf;
	if(obj != NULL)
	{
		stbuf.st_mode = obj->mode;
		stbuf.st_ino = obj->lno;
		stbuf.st_uid = obj->uid;
		stbuf.st_gid = obj->gid;
		stbuf.st_size = obj->size;
		stbuf.st_atime = obj->atime;
		stbuf.st_mtime = obj->mtime;
		stbuf.st_ctime = obj->ctime;
		general_stat(&stbuf);
	}
	server_fstat_cbk (frame, NULL, frame->this, 0,
			0, &stbuf);

	return 0;
err:
	server_fstat_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL);
	return 0;
}


	int
server_fstat (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_fstat_req_t  *req = NULL;
	server_state_t      *state = NULL;

	req   = gf_param (hdr);
	state = CALL_STATE (frame);

	/*
	 * return right file size 
	 */
	state->resolve.type    = RESOLVE_ALL;
	state->resolve.fd_no   = ntoh64 (req->fd);

	resolve_and_resume (frame, server_fstat_resume);

	return 0;
}

int
server_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      struct stat *postbuf)
{
        gf_hdr_common_t        *hdr = NULL;
        gf_fop_ftruncate_rsp_t *rsp = NULL;
        size_t                  hdrlen = 0;
        int32_t                 gf_errno = 0;
        server_state_t         *state = NULL;
		uint64_t 	   objaddr = 0;
		server_obj_t    *sobj = NULL;

        hdrlen = gf_hdr_len (rsp, 0);
        hdr    = gf_hdr_new (rsp, 0);
        rsp    = gf_param (hdr);

        hdr->rsp.op_ret = hton32 (op_ret);
        gf_errno        = gf_errno_to_error (op_errno);
        hdr->rsp.op_errno = hton32 (gf_errno);

        state = CALL_STATE (frame);
        if (op_ret == 0) {
                gf_stat_from_stat (&rsp->poststat, postbuf);
				if(state->fd->object->location == OBJ_LOCALHOST){
						object_ctx_get(state->fd->object, this, &objaddr);
						sobj = (server_obj_t *)(long)objaddr; 
						if(sobj != NULL) {
								server_update_change_object(sobj->object, this, FD_DIRTY, 0);
						}
				}

        } else {

                gf_log (this->name, GF_LOG_DEBUG,
                        "%"PRId64": FTRUNCATE %"PRId64" (%"PRId64") ==> %"PRId32" (%s)",
                        frame->root->unique, state->resolve.fd_no,
                        state->fd ? state->fd->object->ono : 0, op_ret,
                        strerror (op_errno));
        }

        protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_FTRUNCATE,
                               hdr, hdrlen, NULL, 0, NULL);

        return 0;
}

int
server_ftruncate_resume (call_frame_t *frame, xlator_t *bound_xl)
{
        server_state_t    *state = NULL;

        state = CALL_STATE (frame);

        if (state->resolve.op_ret != 0)
                goto err;

        STACK_WIND (frame, server_ftruncate_cbk,
                    bound_xl, bound_xl->fops->ftruncate,
                    state->fd, state->offset);
        return 0;
err:
        server_ftruncate_cbk (frame, NULL, frame->this, state->resolve.op_ret,
                              state->resolve.op_errno, NULL);

        return 0;
}

int
server_ftruncate (call_frame_t *frame, xlator_t *bound_xl,
                  gf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
        gf_fop_ftruncate_req_t  *req = NULL;
        server_state_t          *state = NULL;

        req = gf_param (hdr);
        state = CALL_STATE (frame);

        state->resolve.type   = RESOLVE_ALL;
        state->resolve.fd_no  = ntoh64 (req->fd);
        state->offset         = ntoh64 (req->offset);

        resolve_and_resume (frame, server_ftruncate_resume);

        return 0;
}

int
server_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, 
                     struct stat *postbuf)
{
        gf_hdr_common_t       *hdr = NULL;
        gf_fop_truncate_rsp_t *rsp = NULL;
        server_state_t        *state = NULL;
        size_t                 hdrlen = 0;
        int32_t                gf_errno = 0;
		uint64_t 	   objaddr = 0;
		server_obj_t    *sobj = NULL;

        state = CALL_STATE (frame);

        hdrlen = gf_hdr_len (rsp, 0);
        hdr    = gf_hdr_new (rsp, 0);
        rsp    = gf_param (hdr);

        hdr->rsp.op_ret = hton32 (op_ret);
        gf_errno        = gf_errno_to_error (op_errno);
        hdr->rsp.op_errno = hton32 (gf_errno);

        if (op_ret == 0) {
                gf_stat_from_stat (&rsp->poststat, postbuf);
				if(state->fd->object->location == OBJ_LOCALHOST){
						object_ctx_get(state->fd->object, this, &objaddr);
						sobj = (server_obj_t *)(long)objaddr; 
						if(sobj != NULL) {
								server_update_change_object(sobj->object, this, FD_DIRTY, 0);
						}
				}
                gf_stat_from_stat (&rsp->poststat, postbuf);
        } else {
                gf_log (this->name, GF_LOG_DEBUG,
                        "%"PRId64": TRUNCATE %s ==> %"PRId32" (%s)",
                        frame->root->unique, state->loc.path,
                        op_ret, strerror (op_errno));
        }

        protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_TRUNCATE,
                               hdr, hdrlen, NULL, 0, NULL);

        return 0;
}

int
server_truncate_resume (call_frame_t *frame, xlator_t *bound_xl)
{
        server_state_t *state = NULL;

        state = CALL_STATE (frame);

        if (state->resolve.op_ret != 0)
                goto err;

        STACK_WIND (frame, server_truncate_cbk,
                    bound_xl, bound_xl->fops->truncate,
                    &state->loc, state->offset);
        return 0;
err:
        server_truncate_cbk (frame, NULL, frame->this, state->resolve.op_ret,
                             state->resolve.op_errno, NULL);
        return 0;
}

int
server_truncate (call_frame_t *frame, xlator_t *bound_xl,
                 gf_hdr_common_t *hdr, size_t hdrlen,
                 struct iobuf *iobuf)
{
        gf_fop_truncate_req_t *req = NULL;
        server_state_t        *state = NULL;

        req   = gf_param (hdr);
        state = CALL_STATE (frame);

        state->resolve.type  = RESOLVE_ALL;
        state->resolve.path  = strdup (req->path);
        state->offset        = ntoh64 (req->offset);

        resolve_and_resume (frame, server_truncate_resume);

        return 0;
}


/*
 * server_stat_cbk - stat callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @stbuf:
 *
 * not for external reference
 */
	int
server_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	gf_hdr_common_t   *hdr = NULL;
	gf_fop_stat_rsp_t *rsp = NULL;
	server_state_t    *state = NULL;
	size_t             hdrlen = 0;
	//int32_t            gf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	//gf_errno        = gf_errno_to_error (op_errno);
	gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno_to_error (op_errno));

	if (op_ret == 0) {
		gf_stat_from_stat (&rsp->stat, stbuf);
	} else {
		gf_log (this->name, GF_LOG_DEBUG,
				"%"PRId64": STAT %s  ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path,
				op_ret, strerror (op_errno));
	}

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_STAT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

	int
server_stat_resume (call_frame_t *frame, xlator_t *bound_xl)
{
	server_state_t *state = NULL;

	state = CALL_STATE (frame);

	if(state->resolve.op_ret < 0) //object is not exist , error !!!
		goto err;

	object_t * obj = state->loc.object;
	struct stat stbuf;
	if(obj != NULL)
	{
		stbuf.st_mode = obj->mode;
		stbuf.st_ino = obj->lno;
		stbuf.st_uid = obj->uid;
		stbuf.st_gid = obj->gid;
		stbuf.st_size = obj->size;
		stbuf.st_atime = obj->atime;
		stbuf.st_mtime = obj->mtime;
		stbuf.st_ctime = obj->ctime;
		general_stat(&stbuf);
	}
	server_stat_cbk (frame, NULL, frame->this, 0,
			0, &stbuf);

	return 0;
err:
	server_stat_cbk (frame, NULL, frame->this, state->resolve.op_ret,
			state->resolve.op_errno, NULL);
	return 0;
}

	int
server_stat (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_stat_req_t *req = NULL;
	server_state_t    *state = NULL;
	int32_t		    ret = -1;

	req = gf_param (hdr);
	state = CALL_STATE (frame);
	{
		state->resolve.type  = RESOLVE_OBJECT;
		state->resolve.path  = strdup (req->path);
		state->path 	     = req->path;
	}

	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_stat_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL);
		return -1;
	}  
#ifndef YUTIME
	resolve_and_resume (frame, server_stat_resume);
#else
	long long t1=0, t2=0;
	t1 = usec();
	resolve_and_resume (frame, server_stat_resume);
	t2 = usec();
	gf_log ("YUT", GF_LOG_ERROR,"statresolve NS use %lld ", t2-t1);
#endif
	return 0;
}


/* xxx_MOPS */
	int
_volfile_update_checksum (xlator_t *this, char *key, uint32_t checksum)
{
	server_conf_t       *conf         = NULL;
	struct _volfile_ctx *temp_volfile = NULL;

	conf         = this->private;
	temp_volfile = conf->volfile;

	while (temp_volfile) {
		if ((NULL == key) && (NULL == temp_volfile->key))
			break;
		if ((NULL == key) || (NULL == temp_volfile->key)) {
			temp_volfile = temp_volfile->next;
			continue;
		}
		if (strcmp (temp_volfile->key, key) == 0)
			break;
		temp_volfile = temp_volfile->next;
	}

	if (!temp_volfile) {
		temp_volfile = CALLOC (1, sizeof (struct _volfile_ctx));

		temp_volfile->next  = conf->volfile;
		temp_volfile->key   = (key)? strdup (key): NULL;
		temp_volfile->checksum = checksum;

		conf->volfile = temp_volfile;
		goto out;
	}

	if (temp_volfile->checksum != checksum) {
		gf_log (this->name, GF_LOG_CRITICAL, 
				"the volume file got modified between earlier access "
				"and now, this may lead to inconsistency between "
				"clients, advised to remount client");
		temp_volfile->checksum  = checksum;
	}

out:
	return 0;
}

	size_t 
build_volfile_path (xlator_t *this, const char *key, char *path, 
		size_t path_len)
{
	int   ret = -1;
	int   free_filename = 0;
	char *filename = NULL;
	char  data_key[256] = {0,};

	/* Inform users that this option is changed now */
	ret = dict_get_str (this->options, "client-volume-filename", 
			&filename);
	if (ret == 0) {
		gf_log (this->name, GF_LOG_WARNING,
				"option 'client-volume-filename' is changed to "
				"'volume-filename.<key>' which now takes 'key' as an "
				"option to choose/fetch different files from server. "
				"Refer documentation or contact developers for more "
				"info. Currently defaulting to given file '%s'", 
				filename);
	}

	if (key && !filename) {
		sprintf (data_key, "volume-filename.%s", key);
		ret = dict_get_str (this->options, data_key, &filename);
		if (ret < 0) {
			/* Make sure that key doesn't contain 
			 * "../" in path 
			 */
			if (!strstr (key, "../")) {
				asprintf (&filename, "%s/%s.vol", 
						CONFDIR, key);
				free_filename = 1;
			} else {
				gf_log (this->name, GF_LOG_DEBUG,
						"%s: invalid key", key);
			}
		} 
	}

	if (!filename) {
		ret = dict_get_str (this->options, 
				"volume-filename.default", &filename);
		if (ret < 0) {
			gf_log (this->name, GF_LOG_DEBUG,
					"no default volume filename given, "
					"defaulting to %s", DEFAULT_VOLUME_FILE_PATH);

			filename = DEFAULT_VOLUME_FILE_PATH;
		}
	}

	ret = -1;
	if ((filename) && (path_len > strlen (filename))) {
		strcpy (path, filename);
		ret = strlen (filename);
	}

	if (free_filename)
		free (filename);

	return ret;
}

	int 
_validate_volfile_checksum (xlator_t *this, char *key,
		uint32_t checksum)
{        
	char                 filename[ZR_PATH_MAX] = {0,};
	server_conf_t       *conf         = NULL;
	struct _volfile_ctx *temp_volfile = NULL;
	int                  ret          = 0;
	uint32_t             local_checksum = 0;

	conf         = this->private;
	temp_volfile = conf->volfile;

	if (!checksum) 
		goto out;

	if (!temp_volfile) {
		ret = build_volfile_path (this, key, filename, 
				sizeof (filename));
		if (ret <= 0)
			goto out;
		ret = open (filename, O_RDONLY);
		if (-1 == ret) {
			ret = 0;
			gf_log (this->name, GF_LOG_DEBUG,
					"failed to open volume file (%s) : %s",
					filename, strerror (errno));
			goto out;
		}
		get_checksum_for_file (ret, &local_checksum);
		_volfile_update_checksum (this, key, local_checksum);
		close (ret);
	}

	temp_volfile = conf->volfile;
	while (temp_volfile) {
		if ((NULL == key) && (NULL == temp_volfile->key))
			break;
		if ((NULL == key) || (NULL == temp_volfile->key)) {
			temp_volfile = temp_volfile->next;
			continue;
		}
		if (strcmp (temp_volfile->key, key) == 0)
			break;
		temp_volfile = temp_volfile->next;
	}

	if (!temp_volfile)
		goto out;

	if ((temp_volfile->checksum) && 
			(checksum != temp_volfile->checksum)) 
		ret = -1;

out:
	return ret;
}

/* Management Calls */
/*
 * mop_getspec - getspec function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params:
 *
 */
	int
mop_getspec (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_hdr_common_t      *_hdr = NULL;
	gf_mop_getspec_rsp_t *rsp = NULL;
	int32_t               ret = -1;
	int32_t               op_errno = ENOENT;
	int32_t               gf_errno = 0;
	int32_t               spec_fd = -1;
	size_t                file_len = 0;
	size_t                _hdrlen = 0;
	char                  filename[ZR_PATH_MAX] = {0,};
	struct stat           stbuf = {0,};
	gf_mop_getspec_req_t *req = NULL;
	uint32_t              checksum = 0;
	//uint32_t              flags  = 0;
	uint32_t              keylen = 0;
	char                 *key = NULL;
	server_conf_t        *conf = NULL;

	req   = gf_param (hdr);
	//flags = ntoh32 (req->flags);
	keylen = ntoh32 (req->keylen);
	if (keylen) {
		key = req->key;
	}

	conf = frame->this->private;

	ret = build_volfile_path (frame->this, key, filename, 
			sizeof (filename));
	if (ret > 0) {
		/* to allocate the proper buffer to hold the file data */
		ret = stat (filename, &stbuf);
		if (ret < 0){
			gf_log (frame->this->name, GF_LOG_ERROR,
					"Unable to stat %s (%s)", 
					filename, strerror (errno));
			goto fail;
		}

		spec_fd = open (filename, O_RDONLY);
		if (spec_fd < 0) {
			gf_log (frame->this->name, GF_LOG_ERROR,
					"Unable to open %s (%s)", 
					filename, strerror (errno));
			goto fail;
		}
		ret = 0;
		file_len = stbuf.st_size;
		if (conf->verify_volfile_checksum) {
			get_checksum_for_file (spec_fd, &checksum);
			_volfile_update_checksum (frame->this, key, checksum);
		}
	} else {
		errno = ENOENT;
	}

fail:
	op_errno = errno;

	_hdrlen = gf_hdr_len (rsp, file_len + 1);
	_hdr    = gf_hdr_new (rsp, file_len + 1);
	rsp     = gf_param (_hdr);

	_hdr->rsp.op_ret = hton32 (ret);
	gf_errno         = gf_errno_to_error (op_errno);
	_hdr->rsp.op_errno = hton32 (gf_errno);

	if (file_len) {
		ret = read (spec_fd, rsp->spec, file_len);
		close (spec_fd);
	}
	protocol_server_reply (frame, GF_OP_TYPE_MOP_REPLY, GF_MOP_GETSPEC,
			_hdr, _hdrlen, NULL, 0, NULL);

	return 0;
}


	int
server_checksum_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno,
		uint8_t *fchecksum, uint8_t *dchecksum)
{
	gf_hdr_common_t       *hdr = NULL;
	gf_fop_checksum_rsp_t *rsp = NULL;
	size_t                 hdrlen = 0;
	int32_t                gf_errno = 0;

	hdrlen = gf_hdr_len (rsp, ZR_FILENAME_MAX + 1 + ZR_FILENAME_MAX + 1);
	hdr    = gf_hdr_new (rsp, ZR_FILENAME_MAX + 1 + ZR_FILENAME_MAX + 1);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	if (op_ret >= 0) {
		memcpy (rsp->fchecksum, fchecksum, ZR_FILENAME_MAX);
		rsp->fchecksum[ZR_FILENAME_MAX] =  '\0';
	} 

	protocol_server_reply (frame, GF_OP_TYPE_FOP_REPLY, GF_FOP_CHECKSUM,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


	int
server_checksum (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_fop_checksum_req_t *req = NULL;
	server_state_t        *state = NULL;

	req = gf_param (hdr);

	state->path  = req->path;

	gf_log (bound_xl->name, GF_LOG_TRACE,
			"%"PRId64": CHECKSUM %s", 
			frame->root->unique, state->path);

	/* TODO: implement this */
	return 0;
}


/*
 * mop_unlock - unlock management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_getvolume (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	return 0;
}

struct __get_xl_struct {
	const char *name;
	xlator_t *reply;
};

void __check_and_set (xlator_t *each, void *data)
{
	if (!strcmp (each->name,
				((struct __get_xl_struct *) data)->name))
		((struct __get_xl_struct *) data)->reply = each;
}

	static xlator_t *
get_xlator_by_name (xlator_t *some_xl, const char *name)
{
	struct __get_xl_struct get = {
		.name = name,
		.reply = NULL
	};

	xlator_foreach (some_xl, __check_and_set, &get);

	return get.reply;
}


/*
 * mop_setvolume - setvolume management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_setvolume (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *req_hdr, size_t req_hdrlen,
		struct iobuf *iobuf)
{
	server_connection_t         *conn = NULL;
	server_conf_t               *conf = NULL;
	gf_hdr_common_t             *rsp_hdr = NULL;
	gf_mop_setvolume_req_t      *req = NULL;
	gf_mop_setvolume_rsp_t      *rsp = NULL;
	peer_info_t                 *peerinfo = NULL;
	int32_t                      ret = -1;
	int32_t                      op_ret = -1;
	int32_t                      op_errno = EINVAL;
	int32_t                      gf_errno = 0;
	dict_t                      *reply = NULL;
	dict_t                      *config_params = NULL;
	dict_t                      *params = NULL;
	char                        *name = NULL;
	char                        *version = NULL;
	char                        *process_uuid = NULL;
	xlator_t                    *xl = NULL;
	transport_t                 *trans = NULL;
	size_t                       rsp_hdrlen = -1;
	size_t                       dict_len = -1;
	size_t                       req_dictlen = -1;
	char                        *msg = NULL;
	char                        *volfile_key = NULL;
	uint32_t                     checksum = 0;
	int32_t                      lru_limit = 1024;

	params = dict_new ();
	reply  = dict_new ();

	req    = gf_param (req_hdr);
	req_dictlen = ntoh32 (req->dict_len);
	ret = dict_unserialize (req->buf, req_dictlen, &params);

	config_params = dict_copy_with_ref (frame->this->options, NULL);
	trans         = TRANSPORT_FROM_FRAME(frame);
	conf          = SERVER_CONF(frame);

	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"Internal error: failed to unserialize "
				"request dictionary");
		if (ret < 0)
			gf_log (bound_xl->name, GF_LOG_DEBUG,
					"failed to set error msg \"%s\"",
					"Internal error: failed to unserialize "
					"request dictionary");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = dict_get_str (params, "process-uuid", &process_uuid);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"UUID not specified");
		if (ret < 0)
			gf_log (bound_xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}


	conn = server_connection_get (frame->this, process_uuid);
	if (trans->xl_private != conn)
		trans->xl_private = conn;

	ret = dict_get_str (params, "protocol-version", &version);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"No version number specified");
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = strcmp (version, GF_PROTOCOL_VERSION);
	if (ret != 0) {
		asprintf (&msg,
				"protocol version mismatch: client(%s) - server(%s)",
				version, GF_PROTOCOL_VERSION);
		ret = dict_set_dynstr (reply, "ERROR", msg);
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = dict_get_str (params,
			"remote-subvolume", &name);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"No remote-subvolume option specified");
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	xl = get_xlator_by_name (frame->this, name);
	if (xl == NULL) {
		asprintf (&msg, "remote-subvolume \"%s\" is not found", name);
		ret = dict_set_dynstr (reply, "ERROR", msg);
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = ENOENT;
		goto fail;
	}

	if (conf->verify_volfile_checksum) {
		ret = dict_get_uint32 (params, "volfile-checksum", &checksum);
		if (ret == 0) {
			ret = dict_get_str (params, "volfile-key", 
					&volfile_key);

			ret = _validate_volfile_checksum (trans->xl, 
					volfile_key, 
					checksum);
			if (-1 == ret) {
				ret = dict_set_str (reply, "ERROR",
						"volume-file checksum "
						"varies from earlier "
						"access");
				if (ret < 0)
					gf_log (trans->xl->name, GF_LOG_DEBUG,
							"failed to set error msg");

				op_ret   = -1;
				op_errno = ESTALE;
				goto fail;
			}
		}
	}


	peerinfo = &trans->peerinfo;
	ret = dict_set_static_ptr (params, "peer-info", peerinfo);
	if (ret < 0)
		gf_log (trans->xl->name, GF_LOG_DEBUG,
				"failed to set peer-info");

	if (conf->auth_modules == NULL) {
		gf_log (trans->xl->name, GF_LOG_ERROR,
				"Authentication module not initialized");
	}

	ret = gf_authenticate (params, config_params, 
			conf->auth_modules);
	if (ret == AUTH_ACCEPT) {
		gf_log (trans->xl->name, GF_LOG_INFO,
				"accepted client from %s",
				peerinfo->identifier);
		op_ret = 0;
		conn->bound_xl = xl;
		ret = dict_set_str (reply, "ERROR", "Success");
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG,
					"failed to set error msg");
	} else {
		gf_log (trans->xl->name, GF_LOG_ERROR,
				"Cannot authenticate client from %s",
				peerinfo->identifier);
		op_ret = -1;
		op_errno = EACCES;
		ret = dict_set_str (reply, "ERROR", "Authentication failed");
		if (ret < 0)
			gf_log (bound_xl->name, GF_LOG_DEBUG,
					"failed to set error msg");

		goto fail;
	}

	if (conn->bound_xl == NULL) {
		ret = dict_set_str (reply, "ERROR",
				"Check volfile and handshake "
				"options in protocol/client");
		if (ret < 0)
			gf_log (trans->xl->name, GF_LOG_DEBUG, 
					"failed to set error msg");

		op_ret = -1;
		op_errno = EACCES;
		goto fail;
	}

	if ((conn->bound_xl != NULL) &&
			(ret >= 0)                   &&
			(conn->bound_xl->otable == NULL)) {
		/* create object table for this bound_xl, if one doesn't 
		   already exist */
		lru_limit = OBJECT_LRU_LIMIT (frame->this);

		gf_log (trans->xl->name, GF_LOG_TRACE,
				"creating object table with lru_limit=%"PRId32", "
				"xlator=%s", lru_limit, conn->bound_xl->name);

		conn->bound_xl->otable = 
			object_table_new (lru_limit,
					conn->bound_xl);
	}

	ret = dict_set_str (reply, "process-uuid", 
			xl->ctx->process_uuid);

	ret = dict_set_uint64 (reply, "transport-ptr",
			((uint64_t) (long) trans));

fail:
	dict_len = dict_serialized_length (reply);
	if (dict_len < 0) {
		gf_log (xl->name, GF_LOG_DEBUG,
				"failed to get serialized length of reply dict");
		op_ret   = -1;
		op_errno = EINVAL;
		dict_len = 0;
	}

	rsp_hdr    = gf_hdr_new (rsp, dict_len);
	rsp_hdrlen = gf_hdr_len (rsp, dict_len);
	rsp = gf_param (rsp_hdr);

	if (dict_len) {
		ret = dict_serialize (reply, rsp->buf);
		if (ret < 0) {
			gf_log (xl->name, GF_LOG_DEBUG,
					"failed to serialize reply dict");
			op_ret = -1;
			op_errno = -ret;
		}
	}
	rsp->dict_len = hton32 (dict_len);

	rsp_hdr->rsp.op_ret = hton32 (op_ret);
	gf_errno = gf_errno_to_error (op_errno);
	rsp_hdr->rsp.op_errno = hton32 (gf_errno);

	protocol_server_reply (frame, GF_OP_TYPE_MOP_REPLY, GF_MOP_SETVOLUME,
		rsp_hdr, rsp_hdrlen, NULL, 0, NULL);

	dict_unref (params);
	dict_unref (reply);
	dict_unref (config_params);

	return 0;
}

/*
 * server_mop_stats_cbk - stats callback for server management operation
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 * @stats:err
 *
 * not for external reference
 */

	int
server_mop_stats_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t ret, int32_t op_errno,
		struct xlator_stats *stats)
{
	/* TODO: get this information from somewhere else, not extern */
	gf_hdr_common_t    *hdr = NULL;
	gf_mop_stats_rsp_t *rsp = NULL;
	char                buffer[256] = {0,};
	int64_t             hadafsd_stats_nr_clients = 0;
	size_t              hdrlen = 0;
	size_t              buf_len = 0;
	int32_t             gf_errno = 0;

	if (ret >= 0) {
		sprintf (buffer,
				"%"PRIx64",%"PRIx64",%"PRIx64
				",%"PRIx64",%"PRIx64",%"PRIx64
				",%"PRIx64",%"PRIx64"\n",
				stats->nr_files, stats->disk_usage, stats->free_disk,
				stats->total_disk_size, stats->read_usage,
				stats->write_usage, stats->disk_speed,
				hadafsd_stats_nr_clients);

		buf_len = strlen (buffer);
	}

	hdrlen = gf_hdr_len (rsp, buf_len + 1);
	hdr    = gf_hdr_new (rsp, buf_len + 1);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (ret);
	gf_errno        = gf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (gf_errno);

	strcpy (rsp->buf, buffer);

	protocol_server_reply (frame, GF_OP_TYPE_MOP_REPLY, GF_MOP_STATS,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * mop_unlock - unlock management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_stats (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	int32_t             flag = 0;
	gf_mop_stats_req_t *req = NULL;

	req = gf_param (hdr);

	flag = ntoh32 (req->flags);

	STACK_WIND (frame, server_mop_stats_cbk,
			bound_xl,
			bound_xl->mops->stats,
			flag);

	return 0;
}


	int
mop_ping (call_frame_t *frame, xlator_t *bound_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	gf_hdr_common_t     *rsp_hdr = NULL;
	gf_mop_ping_rsp_t   *rsp = NULL;
	size_t               rsp_hdrlen = 0;

	rsp_hdrlen = gf_hdr_len (rsp, 0);
	rsp_hdr    = gf_hdr_new (rsp, 0);

	hdr->rsp.op_ret = 0;

	protocol_server_reply (frame, GF_OP_TYPE_MOP_REPLY, GF_MOP_PING,
			rsp_hdr, rsp_hdrlen, NULL, 0, NULL);

	return 0;
}
/*
 * unknown_op_cbk - This function is called when a opcode for unknown 
 *                  type is called. Helps to keep the backward/forward
 *                  compatiblity
 * @frame: call frame
 * @type:
 * @opcode:
 *
 */

	int
unknown_op_cbk (call_frame_t *frame, int32_t type, int32_t opcode)
{
	gf_hdr_common_t    *hdr = NULL;
	gf_fop_flush_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             gf_errno = 0;

	hdrlen = gf_hdr_len (rsp, 0);
	hdr    = gf_hdr_new (rsp, 0);
	rsp    = gf_param (hdr);

	hdr->rsp.op_ret = hton32 (-1);
	gf_errno        = gf_errno_to_error (ENOSYS);
	hdr->rsp.op_errno = hton32 (gf_errno);

	protocol_server_reply (frame, type, opcode,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * get_frame_for_transport - get call frame for specified transport object
 *
 * @trans: transport object
 *
 */
	static call_frame_t *
get_frame_for_transport (transport_t *trans)
{
	call_frame_t         *frame = NULL;
	call_pool_t          *pool = NULL;
	server_connection_t  *conn = NULL;
	server_state_t       *state = NULL;;

	GF_VALIDATE_OR_GOTO("server", trans, out);

	if (trans->xl && trans->xl->ctx)
		pool = trans->xl->ctx->pool;
	GF_VALIDATE_OR_GOTO("server", pool, out);

	frame = create_frame (trans->xl, pool);
	GF_VALIDATE_OR_GOTO("server", frame, out);

	state = CALLOC (1, sizeof (*state));
	GF_VALIDATE_OR_GOTO("server", state, out);

	conn = trans->xl_private;
	if (conn) {
		if (conn->bound_xl)
			state->otable = conn->bound_xl->otable;
		state->bound_xl = conn->bound_xl;
	}

	state->trans = transport_ref (trans);
	state->loc.path = NULL;
	state->loc.sid = NULL;
	state->resolve.set_close = 0;

	frame->root->trans = conn;
	frame->root->state = state;        /* which socket */
	frame->root->unique = 0;           /* which call */

out:
	return frame;
}

/*
 * get_frame_for_call - create a frame into the capable of
 *                      generating and replying the reply packet by itself.
 *                      By making a call with this frame, the last UNWIND
 *                      function will have all needed state from its
 *                      frame_t->root to send reply.
 * @trans:
 * @blk:
 * @params:
 *
 * not for external reference
 */
	static call_frame_t *
get_frame_for_call (transport_t *trans, gf_hdr_common_t *hdr)
{
	call_frame_t *frame = NULL;

	frame = get_frame_for_transport (trans);

	frame->root->op   = ntoh32 (hdr->op);
	frame->root->type = ntoh32 (hdr->type);

	frame->root->uid         = ntoh32 (hdr->req.uid);
	frame->root->unique      = ntoh64 (hdr->callid);      /* which call */
	frame->root->gid         = ntoh32 (hdr->req.gid);
	frame->root->pid         = ntoh32 (hdr->req.pid);

	return frame;
}

/*
 * prototype of operations function for each of mop and
 * fop at server protocol level
 *
 * @frame: call frame pointer
 * @bound_xl: the xlator that this frame is bound to
 * @params: parameters dictionary
 *
 * to be used by protocol interpret, _not_ for exterenal reference
 */
typedef int32_t (*gf_op_t) (call_frame_t *frame, xlator_t *bould_xl,
		gf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf);


static gf_op_t gf_fops[] = {
	[GF_FOP_UNLINK]       =  server_unlink,
	[GF_FOP_STAT]	      =  server_stat,
	[GF_FOP_FSTAT]	      =  server_fstat,
	[GF_FOP_OPEN]         =  server_open,
	[GF_FOP_READ]         =  server_readv,
	[GF_FOP_WRITE]        =  server_writev,
	[GF_FOP_FLUSH]        =  server_flush,
	[GF_FOP_IOCTL]        =  server_ioctl,
	[GF_FOP_CHECKSUM]     =  server_checksum,
	[GF_FOP_TRUNCATE]     =  server_truncate,
	[GF_FOP_FTRUNCATE]     =  server_ftruncate
};



static gf_op_t gf_mops[] = {
	[GF_MOP_SETVOLUME] = mop_setvolume,
	[GF_MOP_GETVOLUME] = mop_getvolume,
	[GF_MOP_STATS]     = mop_stats,
	[GF_MOP_GETSPEC]   = mop_getspec,
	[GF_MOP_PING]      = mop_ping,
};

static gf_op_t gf_cbks[] = {
	[GF_CBK_FORGET]	    = server_forget,
	[GF_CBK_RELEASE]    = server_release,
};

	int
protocol_server_interpret (xlator_t *this, transport_t *trans,
		char *hdr_p, size_t hdrlen, struct iobuf *iobuf)
{
	server_connection_t         *conn = NULL;
	gf_hdr_common_t             *hdr = NULL;
	xlator_t                    *bound_xl = NULL;
	call_frame_t                *frame = NULL;
	peer_info_t                 *peerinfo = NULL;
	int32_t                      type = -1;
	int32_t                      op = -1;
	int32_t                      ret = -1;

	hdr  = (gf_hdr_common_t *)hdr_p;
	type = ntoh32 (hdr->type);
	op   = ntoh32 (hdr->op);

	conn = trans->xl_private;
	if (conn)
		bound_xl = conn->bound_xl;


	peerinfo = &trans->peerinfo;
	switch (type) {
		case GF_OP_TYPE_FOP_REQUEST:
			if ((op < 0) || (op >= GF_FOP_MAXVALUE)) {
				gf_log (this->name, GF_LOG_ERROR,
						"invalid fop %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			if (bound_xl == NULL) {
				gf_log (this->name, GF_LOG_ERROR,
						"Received fop %"PRId32" before "
						"authentication.", op);
				break;
			}
			frame = get_frame_for_call (trans, hdr);

			ret = gf_fops[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		case GF_OP_TYPE_MOP_REQUEST:
			if ((op < 0) || (op >= GF_MOP_MAXVALUE)) {
				gf_log (this->name, GF_LOG_ERROR,
						"invalid mop %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			frame = get_frame_for_call (trans, hdr);
			ret = gf_mops[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		case GF_OP_TYPE_CBK_REQUEST:
			if ((op < 0) || (op >= GF_CBK_MAXVALUE)) {
				gf_log (this->name, GF_LOG_ERROR,
						"invalid cbk %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			if (bound_xl == NULL) {
				gf_log (this->name, GF_LOG_ERROR,
						"Received cbk %d before authentication.", op);
				break;
			}

			frame = get_frame_for_call (trans, hdr);
			ret = gf_cbks[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		default:
			gf_log ("server", GF_LOG_NORMAL, "invalid type %d, op %d",
					type, op);
			break;
	}

	return ret;
}


/*
 * server_nop_cbk - nop callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 *
 * not for external reference
 */
	int
server_nop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	server_state_t *state = NULL;

	state = CALL_STATE(frame);

	if (state)
		free_state (state);
	STACK_DESTROY (frame->root);
	return 0;
}


	static void
get_auth_types (dict_t *this, char *key, data_t *value, void *data)
{
	dict_t   *auth_dict = NULL;
	char     *saveptr = NULL;
	char     *tmp = NULL;
	char     *key_cpy = NULL;
	int32_t   ret = -1;

	auth_dict = data;
	key_cpy = strdup (key);
	GF_VALIDATE_OR_GOTO("server", key_cpy, out);

	tmp = strtok_r (key_cpy, ".", &saveptr);
	ret = strcmp (tmp, "auth");
	if (ret == 0) {
		tmp = strtok_r (NULL, ".", &saveptr);
		if (strcmp (tmp, "ip") == 0) {
			/* TODO: backward compatibility, remove when 
			   newer versions are available */
			tmp = "addr";
			gf_log ("server", GF_LOG_WARNING, 
					"assuming 'auth.ip' to be 'auth.addr'");
		}
		ret = dict_set_dynptr (auth_dict, tmp, NULL, 0);
		if (ret < 0) {
			gf_log ("server", GF_LOG_DEBUG,
					"failed to dict_set_dynptr");
		} 
	}

	FREE (key_cpy);
out:
	return;
}


	int
validate_auth_options (xlator_t *this, dict_t *dict)
{
	int            ret = -1;
	int            error = 0;
	xlator_list_t *trav = NULL;
	data_pair_t   *pair = NULL;
	char          *saveptr = NULL;
	char          *tmp = NULL;
	char          *key_cpy = NULL;

	trav = this->children;
	while (trav) {
		error = -1;
		for (pair = dict->members_list; pair; pair = pair->next) {
			key_cpy = strdup (pair->key);
			tmp = strtok_r (key_cpy, ".", &saveptr);
			ret = strcmp (tmp, "auth");
			if (ret == 0) {
				/* for module type */
				tmp = strtok_r (NULL, ".", &saveptr); 
				/* for volume name */
				tmp = strtok_r (NULL, ".", &saveptr); 
			}

			if (strcmp (tmp, trav->xlator->name) == 0) {
				error = 0;
				free (key_cpy);
				break;
			}
			free (key_cpy);
		}
		if (-1 == error) {
			gf_log (this->name, GF_LOG_ERROR, 
					"volume '%s' defined as subvolume, but no "
					"authentication defined for the same",
					trav->xlator->name);
			break;
		}
		trav = trav->next;
	}

	return error;
}



/*
 * init - called during server protocol initialization
 *
 * @this:
 *
 */
	int
init (xlator_t *this)
{
	int32_t        ret = -1;
	transport_t   *trans = NULL;
	server_conf_t *conf = NULL;
	data_t        *data = NULL;
	//	char          *nameserver = NULL;
	//	int	      ns_port = -1;

	if (this->children == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
				"protocol/server should have subvolume");
		goto out;
	}

	trans = transport_load (this->options, this);
	if (trans == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
				"failed to load transport");
		goto out;
	}

	ret = transport_listen (trans);
	if (ret == -1) {
		gf_log (this->name, GF_LOG_ERROR,
				"failed to bind/listen on socket");
		goto out;
	}

	conf = CALLOC (1, sizeof (server_conf_t));
	GF_VALIDATE_OR_GOTO(this->name, conf, out);

	INIT_LIST_HEAD (&conf->conns);
	pthread_mutex_init (&conf->mutex, NULL);

	conf->trans = trans;

	conf->auth_modules = dict_new ();
	GF_VALIDATE_OR_GOTO(this->name, conf->auth_modules, out);

	dict_foreach (this->options, get_auth_types, 
			conf->auth_modules);
	ret = validate_auth_options (this, this->options);
	if (ret == -1) {
		// logging already done in validate_auth_options function. 
		goto out;
	}

	ret = gf_auth_init (this, conf->auth_modules);
	if (ret) {
		dict_unref (conf->auth_modules);
		goto out;
	}

	this->private = conf;

	ret = dict_get_int32 (this->options, "object-lru-limit", 
			&conf->object_lru_limit);
	if (ret < 0) {
		conf->object_lru_limit = 1024;
	}

	ret = dict_get_int32 (this->options, "limits.transaction-size", 
			&conf->max_block_size);
	if (ret < 0) {
		gf_log (this->name, GF_LOG_TRACE,
				"defaulting limits.transaction-size to %d",
				DEFAULT_BLOCK_SIZE);
		conf->max_block_size = DEFAULT_BLOCK_SIZE;
	}

	conf->verify_volfile_checksum = 1;
	data = dict_get (this->options, "verify-volfile-checksum");
	if (data) {
		ret = gf_string2boolean(data->data, 
				&conf->verify_volfile_checksum);
		if (ret != 0) {
			gf_log (this->name, GF_LOG_DEBUG,
					"wrong value for verify-volfile-checksum");
			conf->verify_volfile_checksum = 1;
		}
	}

	//chenxi20160229 : redis set up

	data = dict_get (this->options, "name-server");
	if (data) {
		ret = dict_get_int32 (this->options, "ns-port", &ns_port);
		if (ret < 0) {
			gf_log (this->name, GF_LOG_TRACE,
					"defaulting RS_PORT to %d",RS_PORT);
			ns_port = RS_PORT;
		}
		nameserver = data->data;
	}
	else {
		nameserver = NAME_SERVER;
		ns_port = RS_PORT;
	}

	conf->rdc = rd_connect (nameserver, ns_port);
	if (conf->rdc == NULL) {
		ret = -1;
		gf_log (this->name, GF_LOG_ERROR, "connect to name-server failed");
		goto out;
	}

	conf->local_address = NULL;
	data = dict_get (this->options, "local-address");
	if(data) {
		conf->local_address = data->data;
		if(conf->local_address == NULL) {
			gf_log (this->name, GF_LOG_ERROR, "local address not specified");
			ret = -1;
			goto out;
		}
	} else {
		gf_log (this->name, GF_LOG_ERROR, "local address not specified");
		ret = -1;
		goto out;
	}

	//yuting20181226
#ifndef YUT_META
	conf-> update_worker = CALLOC(1, sizeof(conf->update_worker));
	ret = start_update_worker(this, conf->update_worker);
	if( ret == -1 ){
		gf_log(this->name, GF_LOG_ERROR,
				"start process update meta thread failed");
	}
#endif	

#ifndef GF_DARWIN_HOST_OS
	{
		struct rlimit lim;

		lim.rlim_cur = 1048576;
		lim.rlim_max = 1048576;

		if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
			gf_log (this->name, GF_LOG_WARNING,
					"WARNING: Failed to set 'ulimit -n 1M': %s",
					strerror(errno));
			lim.rlim_cur = 65536;
			lim.rlim_max = 65536;

			if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
				gf_log (this->name, GF_LOG_WARNING,
						"Failed to set max open fd to 64k: %s",
						strerror(errno));
			} else {
				gf_log (this->name, GF_LOG_TRACE,
						"max open fd set to 64k");
			}
		}
	}
#endif
	this->ctx->top = this;

	ret = 0;
out:
	return ret;
}



	int
protocol_server_pollin (xlator_t *this, transport_t *trans)
{
	char                *hdr = NULL;
	size_t               hdrlen = 0;
	int                  ret = -1;
	struct iobuf        *iobuf = NULL;


	ret = transport_receive (trans, &hdr, &hdrlen, &iobuf);

	if (ret == 0)
		ret = protocol_server_interpret (this, trans, hdr, 
				hdrlen, iobuf);
	else
		gf_log ("server-protocol", GF_LOG_ERROR, "receive from %s failed when pollin",
				trans->peerinfo.identifier);

	/* TODO: use mem-pool */
	FREE (hdr);

	return ret;
}


/*
 * fini - finish function for server protocol, called before
 *        unloading server protocol.
 *
 * @this:
 *
 */
	void
fini (xlator_t *this)
{
	server_conf_t *conf = this->private;

	GF_VALIDATE_OR_GOTO(this->name, conf, out);

	if (conf->auth_modules) {
		dict_unref (conf->auth_modules);
	}

	FREE (conf);
	this->private = NULL;
out:
	return;
}

/*
 * server_protocol_notify - notify function for server protocol
 * @this:
 * @trans:
 * @event:
 *
 */
	int
notify (xlator_t *this, int32_t event, void *data, ...)
{
	int          ret = 0;
	transport_t *trans = data;
	peer_info_t *peerinfo = NULL;
	peer_info_t *myinfo = NULL;

	if (trans != NULL) {
		peerinfo = &(trans->peerinfo);
		myinfo = &(trans->myinfo);
	}

	switch (event) {
		case GF_EVENT_POLLIN:
			ret = protocol_server_pollin (this, trans);
			break;
		case GF_EVENT_POLLERR:
			{
				gf_log (trans->xl->name, GF_LOG_INFO, "%s disconnected",
						peerinfo->identifier);

				ret = -1;
				transport_disconnect (trans);
				if (trans->xl_private == NULL) {
					gf_log (this->name, GF_LOG_DEBUG,
							"POLLERR received on (%s) even before "
							"handshake with (%s) is successful",
							myinfo->identifier, peerinfo->identifier);
				} else {
					/*
					 * FIXME: shouldn't we check for return value?
					 * what should be done if cleanup fails?
					 */
					server_connection_cleanup (this, trans->xl_private);
				}
			}
			break;

		case GF_EVENT_TRANSPORT_CLEANUP:
			{
				if (trans->xl_private) {
					server_connection_put (this, trans->xl_private);
				} else {
					gf_log (this->name, GF_LOG_DEBUG,
							"transport (%s) cleaned up even before "
							"handshake with (%s) is successful",
							myinfo->identifier, peerinfo->identifier);
				}
			}
			break;

		default:
			default_notify (this, event, data);
			break;
	}

	return ret;
}


struct xlator_mops mops = {
};

struct xlator_fops fops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = {"transport-type"}, 
		.value = {"tcp", "socket", "ib-verbs", "unix", "ib-sdp", 
			"swnet-verbs", "swnet-verbs/server",
			"tcp/server", "ib-verbs/server"},
		.type  = GF_OPTION_TYPE_STR 
	},
	{ .key   = {"volume-filename.*"}, 
		.type  = GF_OPTION_TYPE_PATH, 
	},
	{ .key   = {"object-lru-limit"},  
		.type  = GF_OPTION_TYPE_INT,
		.min   = 0, 
		.max   = (1 * GF_UNIT_MB)
	},
	{ .key   = {"client-volume-filename"}, 
		.type  = GF_OPTION_TYPE_PATH
	}, 
	{ .key   = {"verify-volfile-checksum"}, 
		.type  = GF_OPTION_TYPE_BOOL
	}, 
	{ .key   = {"name-server"},
		.type  = GF_OPTION_TYPE_STR
	},
	{ .key   = {"ns-port"},
		.type  = GF_OPTION_TYPE_STR
	},
	{ .key   = {"local-address"}, 
		.type  = GF_OPTION_TYPE_STR
	},
	{ .key   = {NULL} },
};
