#include "hadafs.h"
#include "xlator.h"
#include "server-protocol.h"
#include "server-helpers.h"
#include <libgen.h>
#include <assert.h>
#include "name-server.h"

int
server_resolve_done (call_frame_t *frame)
{
        server_state_t    *state = NULL;
        xlator_t          *unify_xl = NULL;
	xlator_t	  *this = NULL;

        state = CALL_STATE (frame);
	this = frame->this;

	unify_xl = frame->this->children ? frame->this->children->xlator : NULL;
	assert(unify_xl != NULL);

        state->resume_fn (frame, unify_xl);

	return 0;
}

int
server_resolve_object_local_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct stat *st)
{
        server_state_t     *state = NULL;
        server_resolve_t   *resolve = NULL;
	rd_context_t 	   *rdc = NULL;
	server_conf_t      *conf = NULL;
        loc_t              *loc = NULL;
	object_t 	   *object = NULL;
	uint32_t	   flag = 0;
        int                ret = 0;

        state = CALL_STATE (frame);
        resolve = &(state->resolve);
        loc  = &(state->loc);
	object = loc->object;
	conf = this->private;
	rdc = conf->rdc;

	if(op_ret == -1 && op_errno == ENOENT) {
		ret = ns_del_object(rdc, object);
		gf_log (this->name, GF_LOG_ERROR, "delete orphan object %s\n",
			object->path);
		resolve->op_ret = -1;
		resolve->op_errno = ENOENT;
		goto out;
	}
	if(object->lno != st->st_ino && st->st_ino != 0) {
		gf_log (this->name, GF_LOG_ERROR, 
			"object %s[%s, %lu] maybe replaced by %lu\n",
			object->path, object->ppath, object->lno, st->st_ino);
		resolve->op_ret = -1;
		resolve->op_errno = EAGAIN;
		goto out;
	}

	if(object->size != st->st_size) {
		object->size = st->st_size;
		object->ctime = st->st_ctime;
		object->mtime = st->st_mtime;
		object->atime = st->st_atime;
		flag |= UPDATE_SIZE | UPDATE_CTIME | UPDATE_MTIME | UPDATE_ATIME;
	}
	if(state->resolve.set_close == 1) {
		object->mode = SET_STATUS_BIT_C(object->mode);
		flag |= UPDATE_MODE;
	}
	if(flag != 0 && (object->location == OBJ_LOCALHOST)) {
		/* only localhost of object update ns */
		ret = ns_update_object(rdc, object, flag);
		if(ret < 0) {
			gf_log (this->name, GF_LOG_ERROR, "object %s update failed in ns ",
					object->path);
			resolve->op_ret = -1;
			resolve->op_errno = EINVAL;
		}
	} else {
		resolve->op_ret = 0;
		resolve->op_errno = 0;
	}
out:
	return 0;
}

int
server_resolve_object_local(call_frame_t *frame, object_t *object)
{
        server_state_t     *state = NULL;
        xlator_t           *this = NULL;
        xlator_t           *unify_xl = NULL;
        server_resolve_t   *resolve = NULL;

	state = CALL_STATE (frame);
        this  = frame->this;
	resolve = &(state->resolve);

	resolve->deep_loc.object = object_ref(object);
	resolve->deep_loc.path = strdup(object->path);
	unify_xl = frame->this->children ? frame->this->children->xlator : NULL;

	STACK_WIND (frame, server_resolve_object_local_cbk,
		unify_xl, unify_xl->fops->stat,
		&(resolve->deep_loc));

	return 0;
}

int
server_resolve_object (call_frame_t *frame)
{
        server_state_t     *state = NULL;
        xlator_t           *this = NULL;
        server_resolve_t   *resolve = NULL;
	server_conf_t      *conf = NULL;
	rd_context_t * rdc = NULL;
	int		    need_resolve_local = 0;
        int                 ret = 0;
        loc_t              *loc = NULL;

	state = CALL_STATE (frame);
	this  = frame->this;
	resolve = &(state->resolve);
	loc  = &(state->loc);
	conf = this->private;
	rdc = conf->rdc;

	object_t * object = NULL;
	if(loc->object != NULL)
		object = loc->object;
	else if(state->fd != NULL && state->fd->object != NULL) {
		object = state->fd->object;
		loc->object = object_ref(object);
	} else {  
		//object is not in otable : need object_new
		object = object_new (state->otable, loc->path,
				state->sid, state->soffset);
		if(!object){
			resolve->op_ret = -1;
			resolve->op_errno = ENOMEM;
			goto out;
		}

		loc->object = object;
		
	}

	ret = ns_lookup_object(rdc, object);
	if( ret < 0 ){
		gf_log (this->name, GF_LOG_ERROR,
				"ns_lookup_object %s error", 
				object->path);
		resolve->op_ret = -1;
		resolve->op_errno = EAGAIN;
		goto out;
	} else if(ret == 1){
		resolve->op_ret = 0;
		if(!strcmp(object->lhost, conf->local_address)) {
			object->location = OBJ_LOCALHOST;
			server_resolve_object_local(frame, object);
		} else
			object->location = OBJ_OTHERHOST;
	} else if(ret == 2){
		/* object parent not exist */
		resolve->op_ret = 2;
		resolve->op_errno = ENOENT;
		goto out;
	} else {
		gf_log (this->name, GF_LOG_TRACE,
				"ns_lookup_object : the object %s in not in ns",
				object->path);
		resolve->op_ret = -1;
		resolve->op_errno = ENOENT;
		goto out;
	}
out:
        return 0;
}

int
server_resolve_fd (call_frame_t *frame)
{
        server_state_t       *state = NULL;
        xlator_t             *this = NULL;
        server_resolve_t     *resolve = NULL;
        server_connection_t  *conn = NULL;
        uint64_t              fd_no = -1;

        state = CALL_STATE (frame);
        this  = frame->this;
        resolve = &(state->resolve);
        conn  = SERVER_CONNECTION (frame);

        fd_no = resolve->fd_no;

	state->fd = gf_fd_fdptr_get (conn->fdtable, fd_no);

	if (!state->fd) {
		gf_log ("server-resolve", GF_LOG_DEBUG, "resolve fd error %d", fd_no);
		resolve->op_ret   = -1;
		resolve->op_errno = EBADF;
	} else {
		resolve->op_ret   = 0;
		resolve->op_errno = 0;
	}

	return 0;
}

/*
 * This function is called multiple times, once per resolving one location/fd.
 * state->resolve_now is used to decide which location/fd is to be resolved now
 */
int
server_resolve_all (call_frame_t *frame)
{
        server_state_t    *state = NULL;
        xlator_t          *this = NULL;
	server_resolve_t   *resolve = NULL;
	
        this  = frame->this;
        state = CALL_STATE (frame);
	resolve = &(state->resolve);

        switch (resolve->type) {
		case RESOLVE_NOT:
			resolve->op_ret = 0;
			break;
		case RESOLVE_FD:
			server_resolve_fd (frame);
			break;
		case RESOLVE_ALL:
			server_resolve_fd (frame);
			if(resolve->op_ret == -1) 
				break;
		case RESOLVE_OBJECT:
			server_resolve_object (frame);
			break;
		default:
			resolve->op_ret   = -1;
			resolve->op_errno = EINVAL;
			break;
        }
       	server_resolve_done (frame);
        return 0;
}

int
resolve_and_resume (call_frame_t *frame, server_resume_fn_t fn)
{
        server_state_t    *state = NULL;
        xlator_t          *this  = NULL;

        state = CALL_STATE (frame);
        state->resume_fn = fn;

        this = frame->this;
#ifndef YUTIME
        server_resolve_all (frame);
#else
long long t1=0,t2=0;
	t1=usec();
        server_resolve_all (frame);
	t2=usec();
	  gf_log ("YUT", GF_LOG_ERROR,"fn is %lx %s server_resolve_all NS use %lld ",fn,fn, t2-t1);
#endif
        return 0;
}
