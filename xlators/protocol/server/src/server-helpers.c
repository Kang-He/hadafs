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

#include "server-protocol.h"
#include "server-helpers.h"


/* server_loc_fill - derive a loc_t for a given inode number
 *
 * NOTE: make sure that @loc is empty, because any pointers it holds with reference will
 *       be leaked after returning from here.
 */
int
server_loc_fill (loc_t *loc, server_state_t *state, const char *path)
{
  	object_t *object = NULL;
  	int32_t  ret = -1;

  	GF_VALIDATE_OR_GOTO ("server", loc, out);
  	GF_VALIDATE_OR_GOTO ("server", state, out);
  	GF_VALIDATE_OR_GOTO ("server", path, out);

  	/* anything beyond this point is success */
  	ret = 0;
  	object = loc->object;
  	if (object == NULL) {
  			object = object_search (state->otable, path);
			loc->object = object;
  	}
	
	if(path != NULL)
        	loc->path = strdup(path);
	if(state->sid != NULL) {
		loc->sid = strdup(state->sid);
		loc->soffset = state->soffset;
	}
out:
  	return ret;
}

/*
 * stat_to_str - convert struct stat to a ASCII string
 * @stbuf: struct stat pointer
 *
 * not for external reference
 */
char *
stat_to_str (struct stat *stbuf)
{
	char *tmp_buf = NULL;

	uint64_t dev = stbuf->st_dev;
	uint64_t ino = stbuf->st_ino;
	uint32_t mode = stbuf->st_mode;
	uint32_t nlink = stbuf->st_nlink;
	uint32_t uid = stbuf->st_uid;
	uint32_t gid = stbuf->st_gid;
	uint64_t rdev = stbuf->st_rdev;
	uint64_t size = stbuf->st_size;
	uint32_t blksize = stbuf->st_blksize;
	uint64_t blocks = stbuf->st_blocks;
	uint32_t atime = stbuf->st_atime;
	uint32_t mtime = stbuf->st_mtime;
	uint32_t ctime = stbuf->st_ctime;

	uint32_t atime_nsec = ST_ATIM_NSEC(stbuf);
	uint32_t mtime_nsec = ST_MTIM_NSEC(stbuf);
	uint32_t ctime_nsec = ST_CTIM_NSEC(stbuf);


	asprintf (&tmp_buf,
		  GF_STAT_PRINT_FMT_STR,
		  dev,
		  ino,
		  mode,
		  nlink,
		  uid,
		  gid,
		  rdev,
		  size,
		  blksize,
		  blocks,
		  atime,
		  atime_nsec,
		  mtime,
		  mtime_nsec,
		  ctime,
		  ctime_nsec);

	return tmp_buf;
}

void
server_loc_wipe (loc_t *loc)
{
	
	if (loc->path)
		free ((char *)loc->path);
        if (loc->sid)
		free ((char *)loc->sid);
	
	if (loc->object){
		object_unref (loc->object);
		loc->object = NULL;
	}
}

void
server_resolve_wipe (server_resolve_t *resolve)
{
        struct resolve_comp *comp = NULL;
        int                  i = 0;

        if (resolve->path)
                FREE (resolve->path);

	if (resolve->sid)
                free ((char *)resolve->sid);	

        if (resolve->resolved)
                FREE (resolve->resolved);

        loc_wipe (&resolve->deep_loc);
}


void
free_state (server_state_t *state)
{
	if(state->trans){
		transport_unref (state->trans);
		state->trans = NULL;
	}

	if (state->fd){
		fd_unref (state->fd);
		state->fd = NULL;
	}

	if(state->iobref){
		iobref_unref(state->iobref);
		state->iobref = NULL;
	}

	if (state->iobuf) {
                iobuf_unref (state->iobuf);
                state->iobuf = NULL;
        }

        if (state->volume)
                FREE (state->volume);

	/*if (state->path)
                FREE (state->path);
	
	if (state->sid)
		FREE (state->sid);

	if (state->vmp)
		FREE (state->vmp);*/

	server_loc_wipe(&(state->loc));
	
	server_resolve_wipe (&state->resolve);

	FREE (state);
}

call_frame_t *
server_copy_frame (call_frame_t *frame)
{
	call_frame_t *new_frame = NULL;
	server_state_t *state = NULL, *new_state = NULL;

	state = frame->root->state;

	new_frame = copy_frame (frame);

	new_state = CALLOC (1, sizeof (server_state_t));

	new_frame->root->op    = frame->root->op;
	new_frame->root->type  = frame->root->type;
	new_frame->root->trans = state->trans;
	new_frame->root->state = new_state;

	new_state->bound_xl = state->bound_xl;
	new_state->trans    = transport_ref (state->trans);
	new_state->otable   = state->otable;

	return new_frame;
}

static int32_t
server_connection_cleanup_flush_cbk (call_frame_t *frame,
                                     void *cookie,
                                     xlator_t *this,
                                     int32_t op_ret,
                                     int32_t op_errno)
{
        fd_t *fd = NULL;

        fd = frame->local;

        fd_unref (fd);
        frame->local = NULL;

        STACK_DESTROY (frame->root);
        return 0;
}

int
do_fd_cleanup (xlator_t *this, server_connection_t *conn, call_frame_t *frame,
               fdentry_t *fdentries, int fd_count)
{
        fd_t               *fd = NULL;
        int                 i = 0, ret = -1;
        call_frame_t       *tmp_frame = NULL;
        xlator_t           *bound_xl = NULL;
        
        bound_xl = conn->bound_xl;
        for (i = 0;i < fd_count; i++) {
                fd = fdentries[i].fd;
                
                if (fd != NULL) {
                        tmp_frame = copy_frame (frame);
                        if (tmp_frame == NULL) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "out of memory");
                                goto out;
                        }
                        tmp_frame->local = fd;
                        
                        tmp_frame->root->pid = 0;
                        tmp_frame->root->trans = conn;
                        STACK_WIND (tmp_frame,
                                    server_connection_cleanup_flush_cbk,
                                    bound_xl,
                                    bound_xl->fops->flush,
                                    fd);
                }
        }
        FREE (fdentries);
        ret = 0;

out:
        return ret;
}

int
do_connection_cleanup (xlator_t *this, server_connection_t *conn,
                       struct _lock_table *ltable, fdentry_t *fdentries, int fd_count)
{
        int32_t       ret = 0;
	call_frame_t *frame = NULL;
        server_state_t *state = NULL;

        frame = create_frame (this, this->ctx->pool);
        if (frame == NULL) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                goto out;
        }

        if (fdentries != NULL) {
                ret = do_fd_cleanup (this, conn, frame, fdentries, fd_count);
        }

        state = CALL_STATE (frame);
        if (state)
                free (state);

        STACK_DESTROY (frame->root);

        if (ret) {
                ret = -1;
        }
out:
        return ret;
}

int
server_connection_cleanup (xlator_t *this, server_connection_t *conn)
{
        char                do_cleanup = 0;
	struct _lock_table *ltable = NULL;
        fdentry_t          *fdentries = NULL;
        uint32_t            fd_count = 0;
        int                 ret = 0; 

        if (conn == NULL) {
                goto out;
        }

        pthread_mutex_lock (&conn->lock);
        {
                conn->active_transports--;
                if (conn->active_transports == 0) {
                        if (conn->fdtable) {
                                fdentries = gf_fd_fdtable_get_all_fds (conn->fdtable,
                                                                       &fd_count);
                        }
                        do_cleanup = 1;
                }
        }
        pthread_mutex_unlock (&conn->lock);

        if (do_cleanup && conn->bound_xl)
                ret = do_connection_cleanup (this, conn, ltable, fdentries, fd_count);

out:
        return ret;
}


int
server_connection_destroy (xlator_t *this, server_connection_t *conn)
{
	call_frame_t       *frame = NULL, *tmp_frame = NULL;
	xlator_t           *bound_xl = NULL;
	int32_t             ret = -1;
	server_state_t     *state = NULL;
        fd_t               *fd = NULL; 
        int32_t             i = 0;
        fdentry_t          *fdentries = NULL;
        uint32_t             fd_count = 0;
        
        if (conn == NULL) {
                ret = 0;
                goto out;
        }

	bound_xl = (xlator_t *) (conn->bound_xl);

	if (bound_xl) {
		/* trans will have ref_count = 1 after this call, but its 
		   ok since this function is called in 
		   GF_EVENT_TRANSPORT_CLEANUP */
		frame = create_frame (this, this->ctx->pool);

		state = CALL_STATE (frame);
		if (state)
			free (state);
		STACK_DESTROY (frame->root);

		pthread_mutex_lock (&(conn->lock));
		{
			if (conn->fdtable) {
                                fdentries = gf_fd_fdtable_get_all_fds (conn->fdtable,
                                                                       &fd_count);
				gf_fd_fdtable_destroy (conn->fdtable);
				conn->fdtable = NULL;
			}
		}
		pthread_mutex_unlock (&conn->lock);

                if (fdentries != NULL) {
                        for (i = 0; i < fd_count; i++) {
                                fd = fdentries[i].fd;
                                if (fd != NULL) {
                                        tmp_frame = copy_frame (frame);
                                        tmp_frame->local = fd;

                                        STACK_WIND (tmp_frame,
                                                    server_connection_cleanup_flush_cbk,
                                                    bound_xl,
                                                    bound_xl->fops->flush,
                                                    fd);
                                }
                        }
                        FREE (fdentries);
                }
	}

	gf_log (this->name, GF_LOG_INFO, "destroyed connection of %s",
		conn->id);

	FREE (conn->id);
	FREE (conn);

out:
	return ret;
}


server_connection_t *
server_connection_get (xlator_t *this, const char *id)
{
	server_connection_t *conn = NULL;
	server_connection_t *trav = NULL;
	server_conf_t       *conf = NULL;

	conf = this->private;

	pthread_mutex_lock (&conf->mutex);
	{
		list_for_each_entry (trav, &conf->conns, list) {
			if (!strcmp (id, trav->id)) {
				conn = trav;
				break;
			}
		}

		if (!conn) {
			conn = (void *) CALLOC (1, sizeof (*conn));

			conn->id = strdup (id);
			conn->fdtable = gf_fd_fdtable_alloc ();
			pthread_mutex_init (&conn->lock, NULL);

			list_add (&conn->list, &conf->conns);
		}

		conn->ref++;
                conn->active_transports++;
	}
	pthread_mutex_unlock (&conf->mutex);

	return conn;
}


void
server_connection_put (xlator_t *this, server_connection_t *conn)
{
	server_conf_t       *conf = NULL;
	server_connection_t *todel = NULL;

        if (conn == NULL) {
                goto out;
        }

	conf = this->private;

	pthread_mutex_lock (&conf->mutex);
	{
		conn->ref--;

		if (!conn->ref) {
			list_del_init (&conn->list);
			todel = conn;
		}
	}
	pthread_mutex_unlock (&conf->mutex);

	if (todel) {
		server_connection_destroy (this, todel);
	}

out:
	return;
}
