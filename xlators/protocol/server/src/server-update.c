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

extern char *nameserver;
extern int ns_port;

//yuting201812
#ifdef YUT2019NEEDDEL
server_obj_t * server_obj_new(object_t *object)
{
	server_obj_t *sobj = NULL;

	if (object == NULL) {
		gf_log ("update_redis", GF_LOG_ERROR, "fd NULL ,invalid argument");
		return NULL;
	}
	sobj = CALLOC (1, sizeof (server_obj_t));
	ERR_ABORT (sobj);
	sobj->object = object_ref(object); 
	sobj->fdstat  = FD_NEWOPEN;
	INIT_LIST_HEAD (&sobj->meta_list);

	gf_log ("update_redis", GF_LOG_ERROR, "nnnnnopenfd is %lx", sobj);
	return sobj;

}
#endif

server_obj_t *
server_update_add_openfd(server_obj_t *sobj, server_conf_t *conf)
{
	struct server_update_worker_arg  *worker = conf->update_worker;	

	if (!sobj) {
		gf_log ("update_redis", GF_LOG_ERROR, "openfd is NULL");
		return NULL;
	}

	LOCK (&worker->lock);
	{
		list_add (&sobj->meta_list, &worker->openobjs);
		worker->obj_count++;

	}
	UNLOCK (&worker->lock);

	return sobj;
}


int32_t
server_update_change_object(object_t *object, xlator_t *xl,
		server_fd_state_t state, int delornot)
{
	server_obj_t *sobj = NULL;
	uint64_t   objaddr = 0;

	if (object == NULL || xl == NULL) {
		gf_log_dump_backtrace("object or xlator failed");
		gf_log ("update_redis", GF_LOG_ERROR, "object or xlator is NULL");
		return -1;
	}

	if(!object_ctx_get(object, xl, &objaddr)) {
		sobj = (server_obj_t *)(long)objaddr;
	} else {
		gf_log_dump_backtrace("ctx get failed");
		gf_log ("server-update", GF_LOG_ERROR, "object %s ctx_get failed",
				object->path);
		return -1;
	}
	LOCK (&object->lock);
	{
		sobj->fdstat = state; 
	}
	UNLOCK (&object->lock);

	if(delornot){
		object_ctx_del(object, xl, &objaddr);
	}
	return 0;
}

int  server_update_stat_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *buf)
{
	server_state_t     *state = NULL;
	server_conf_t       *conf = NULL;
	rd_context_t 	    *urdc = NULL;
	object_t *object;	
	int ret = 0, flags = 0;

	conf = this->private;
	state = CALL_STATE(frame);

	object =state->loc.object;

	if (op_ret >= 0 && (object->size != buf->st_size)) {
		gf_log ("update-meta", GF_LOG_TRACE,
				"%"PRId64": update_fstat  %s (%"PRId64")",
				frame->root->unique, object->path, buf->st_ino);

		object->lno = buf->st_ino;
		object->size = buf->st_size;
		object->ctime = buf->st_ctime;
		object->mtime = buf->st_mtime;
		object->atime = buf->st_atime;

		urdc = conf->update_worker->urdc;
		flags=UPDATE_SIZE|UPDATE_MTIME|UPDATE_ATIME|UPDATE_CTIME|UPDATE_MODE;	
		ret = ns_update_object (urdc, object,flags);
		if(ret) {
			gf_log ("server-update", GF_LOG_ERROR, "update ns for %s failed",
					object->path);
		}

	} 
	STACK_DESTROY (frame->root);
	free_state(state);

	return 0;
}


int server_update_stat( server_obj_t *sobj, struct server_update_worker_arg  *worker )
{
	server_state_t *state = NULL;
	call_frame_t *frame = NULL;
	xlator_t *this = worker->xlator;
	int32_t ret = 0;

	frame = create_frame (this, this->ctx->pool);
	GF_VALIDATE_OR_GOTO("server", frame, out);

	state = CALLOC(1, sizeof(server_state_t));
	GF_VALIDATE_OR_GOTO("server", state, out);
	
	state->loc.object = object_ref(sobj->object);	

	ret = server_loc_fill (&(state->loc), state, sobj->object->path);
	if(ret < 0) {
		gf_log("server-update", GF_LOG_ERROR,
			"fill state->loc failed for %s", state->path);
		ret = -1;
		goto out;
	}

	get_posix_path(state->loc.object);
	frame->root->state = state;

	if(frame){
		STACK_WIND (frame, server_update_stat_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->stat,
				&state->loc);
	}
	return 0;
out:
	if(state)
		free_state(state);
	if(frame)
		STACK_DESTROY (frame->root);	
		
	return ret;

}

void server_scan_openfd( struct server_update_worker_arg  *worker)
{

	struct list_head list_tmp;
	struct list_head list_nouse;
	xlator_t *this = worker->xlator;
	server_conf_t       *conf = this->private;
	server_obj_t *sobj = NULL;
	server_obj_t *tmp = NULL;

	INIT_LIST_HEAD(&list_tmp);
	INIT_LIST_HEAD(&list_nouse);


	LOCK (&worker->lock);
	if (!list_empty (&worker->openobjs)) {
		list_for_each_entry_safe (sobj, tmp, &worker->openobjs, meta_list) {
			if(sobj->fdstat == FD_UNLINK || sobj->fdstat == FD_CLOSED) {
				list_del_init(&sobj->meta_list);
				list_add_tail(&sobj->meta_list, &list_nouse);
				worker->obj_count--;
			} else 
				list_add_tail(&sobj->update_list, &list_tmp);
		}
	} else {
		UNLOCK (&worker->lock);
		return;
	}
	UNLOCK (&worker->lock);

	/* update all list_tmp entries */
	if (!list_empty (&list_tmp)) {
		list_for_each_entry_safe (sobj, tmp, &list_tmp, update_list) {
			switch(sobj->fdstat) 
			{
				case FD_NEWOPEN :
					break;
				case FD_DIRTY :
					server_update_stat(sobj, worker);
					server_update_change_object(sobj->object, this, FD_CLEAN, 0);
					break;
				case FD_RELEASE :
					server_update_stat(sobj, worker);
					if(fd_list_empty(sobj->object)) /* wait until memcache flush ok */
						server_update_change_object(sobj->object, this, FD_CLOSED, 1);
					break;
				case FD_CLEAN :
					break;
				default:
					gf_log("update_redis",GF_LOG_ERROR, "fdstat is unkown,what happend???"); 
					break;

			}
			list_del_init(&sobj->update_list);
		}
	}
	/* delete all list_tmp entries */
	if (!list_empty (&list_nouse)) {
		list_for_each_entry_safe (sobj, tmp, &list_nouse, meta_list) {
			switch(sobj->fdstat) 
			{
				case FD_UNLINK:
					gf_log("server-update", GF_LOG_WARNING,
						"unlink delete sobject %s saddr_object %p:%p",
						sobj->object->path, sobj, sobj->object);
					ns_del_object(worker->urdc, sobj->object);	
				case FD_CLOSED:
					gf_log("server-update", GF_LOG_TRACE,
						"delete sobject %s saddr_object %p:%p",
						sobj->object->path, sobj, sobj->object);

					list_del_init(&sobj->meta_list);
					object_unref(sobj->object);
					FREE(sobj);
			}
		}
	}

}


/*yuting 20181226
 *  update all open files metadate to redis
 *
 */
void * server_update_meta(void *data)
{
	struct timeval now;
	struct timespec timeout = {0,};

	struct server_update_worker_arg *worker = data;
	worker->obj_count =0;
	INIT_LIST_HEAD(&worker->openobjs);
	worker->urdc = rd_connect (nameserver, ns_port);

	if (worker->urdc == NULL) {
		gf_log ("update_redis", GF_LOG_ERROR, "connect to name-server failed");
		goto out;
	}

	for(;;){
#if 0
		gettimeofday(&now,NULL);
		//timeout.tv_nsec = time(NULL) + 500000; 
		//tv_usec*1000000=tv_sec;
		timeout.tv_sec = now.tv_sec + 1; 
		LOCK(&worker->lock);
		{
			pthread_cond_timedwait (&worker->cond, &worker->lock, &timeout);
		}
		UNLOCK(&worker->lock);
#endif
		usleep(800000);
		server_scan_openfd(worker);
		continue;
	}

out:
	pthread_exit(NULL);
}

int  start_update_worker(xlator_t *this, struct server_update_worker_arg *worker ){

	int ret = 0;
	worker->xlator = this;
	LOCK_INIT( &worker->lock);
	pthread_cond_init (&worker->cond, NULL);

	ret = pthread_create (&worker->thread, NULL, server_update_meta,worker);
	if (ret == 0) {
		gf_log ("update-redis", GF_LOG_DEBUG,
				"strared threads to update metadate");
	} else {
		free(worker);
	}

	return ret;
}
