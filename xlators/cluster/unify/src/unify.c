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

/**
 * xlators/cluster/unify:
 *     - This xlator is one of the main translator in LWFS, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, unify assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, unify has support for global namespace, which is used to keep a 
 * global view of fs's namespace tree. The stat for directories are taken
 * just from the namespace, where as for files, just 'st_ino' is taken from
 * Namespace node, and other stat info is taken from the actual storage node.
 * Also Namespace node helps to keep consistant inode for files across 
 * lwfs (re-)mounts.
 */

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "unify.h"
#include "dict.h"
#include "xlator.h"
#include "logging.h"
#include "stack.h"
#include "defaults.h"
#include "common-utils.h"
#include <signal.h>
#include <libgen.h>
#include "compat-errno.h"
#include "compat.h"

#define UNIFY_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR(_loc) do { \
  if (!(_loc && _loc->object)) {                            \
    STACK_UNWIND (frame, -1, EINVAL, NULL, NULL, NULL);    \
    return 0;                                              \
  }                                                        \
} while(0)


#define UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR(_fd) do { \
  if (!(_fd && !fd_ctx_get (_fd, this, NULL))) {       \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);      \
    return 0;                                          \
  }                                                    \
} while(0)

#define UNIFY_CHECK_FD_AND_UNWIND_ON_ERR(_fd) do { \
  if (!_fd) {                                      \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);  \
    return 0;                                      \
  }                                                \
} while(0)

/**
 * unify_local_wipe - free all the extra allocation of local->* here.
 */
static void 
unify_local_wipe (unify_local_t *local)
{
	/* Free the strdup'd variables in the local structure */
	if (local->name) {
		FREE (local->name);
	}
	loc_wipe (&local->loc);

	FREE(local);
}

/**
 * unify_open_cbk -
 */
int32_t
unify_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno,
                   fd_t *fd, object_t *object, struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, fd, object, stbuf);

	return 0;
}

/**
 * unify_open - 
 */
int32_t
unify_open (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc,
	    int32_t flags,
	    mode_t mode,
	    fd_t *fd)
{
	unify_private_t *priv = this->private;
	xlator_t*xl = NULL;
	void * tmp = NULL;
	int ret = -1;

	UNIFY_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	ret = dict_get_ptr (priv->xl_array, loc->object->lhost, &tmp);
	if( ret != 0 ){
		gf_log (this->name, GF_LOG_ERROR, "%s:unify can't find right child xlator by %s", loc->object->path, loc->object->lhost);
		STACK_UNWIND (frame, -1, ENODEV, NULL, NULL, NULL);
		return 0;
		
	}

	xl = (xlator_t *)tmp;
	gf_log (this->name, GF_LOG_DEBUG, "unify will send open %s to xlator:%s",loc->path, xl->name);
	fd_ctx_set (fd, this, (uint64_t)(long)xl); // set fd_ctx : unify->tmp_child
	STACK_WIND (frame, unify_open_cbk, xl, xl->fops->open, loc, flags, mode, fd);
	return 0;
}

/**
 * unify_readv_cbk - 
 */
int32_t
unify_readv_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct iovec *vector,
		 int32_t count,
		 struct stat *stbuf,
		 struct iobref *iobref)
{
	STACK_UNWIND (frame, op_ret, op_errno, vector, count, stbuf, iobref);
	return 0;
}

/**
 * unify_readv - 
 */
int32_t
unify_readv (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     size_t size,
	     off_t offset)
{
	UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		gf_log (this->name, GF_LOG_ERROR, "unify get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL, 1, NULL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    unify_readv_cbk,
		    child,
		    child->fops->readv,
		    fd,
		    size,
		    offset);

	return 0;
}

/**
 * unify_writev_cbk - 
 */
int32_t
unify_writev_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
                struct stat *stbuf)
{

	STACK_UNWIND (frame, op_ret, op_errno, stbuf);

	return 0;
}

/**
 * unify_writev - 
 */
int32_t
unify_writev (call_frame_t *frame,
	      xlator_t *this,
	      fd_t *fd,
	      struct iovec *vector,
	      int32_t count,
	      off_t off,
              struct iobref *iobref)
{
	UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;	

	if(!child)
	{
		gf_log (this->name, GF_LOG_ERROR, "unify get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}


	STACK_WIND (frame,
		    unify_writev_cbk,
		    child,
		    child->fops->writev,
		    fd,
		    vector,
		    count,
		    off,
                    iobref);

	return 0;
}

/**
 * unify_flush_cbk - 
 */
int32_t
unify_flush_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno,stbuf);
	return 0;
}

/**
 * unify_flush -
 */
int32_t
unify_flush (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		gf_log (this->name, GF_LOG_ERROR, "unify get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, unify_flush_cbk, child, 
		    child->fops->flush, fd);

	return 0;
}
/**
 * unify_ioctl_cbk - 
 */
int32_t
unify_ioctl_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

/**
 * unify_ioctl - 
 */
int32_t
unify_ioctl (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     uint32_t cmd,
	     uint64_t arg)
{
	UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		gf_log (this->name, GF_LOG_ERROR, "unify get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, unify_ioctl_cbk, child, 
		    child->fops->ioctl, fd, cmd, arg);

	return 0;
}

/**
 * unify_unlink_cbk - 
 */
int32_t
unify_unlink_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno)
{

	STACK_UNWIND (frame, op_ret, op_errno);

	return 0;
}


/**
 * unify_unlink - 
 */
int32_t
unify_unlink (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	unify_private_t *priv        = this->private;
	xlator_t 		*xl 	     = NULL;
	void 		*tmp = NULL;
	int ret = 0;

	UNIFY_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);
	
	ret = dict_get_ptr (priv->xl_array, loc->object->lhost, &tmp);
	if( ret != 0 ){
		gf_log (this->name, GF_LOG_ERROR, "unify can't find right child xlator");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
		
	}

	xl = (xlator_t *)tmp;
	gf_log (this->name, GF_LOG_DEBUG, "unify will send unlink to xlator:%s",xl->name);

	STACK_WIND (frame,unify_unlink_cbk,xl,xl->fops->unlink,loc);

	return 0;
}

/**
 * unify_fstat_cbk - 
 */
int32_t
unify_fstat_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	return 0;
}

/**
 * unify_fstat - 
 */
int32_t
unify_fstat (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	UNIFY_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		gf_log (this->name, GF_LOG_ERROR, "unify get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    unify_fstat_cbk,
		    child,
		    child->fops->fstat,
		    fd);

	return 0;
}

/**
 * unify_stat_cbk -
 */
int32_t
unify_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);

	return 0;
}

/**
 * unify_stat - 
 */
int32_t
unify_stat(call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc)
{
	unify_private_t *priv = this->private;
	xlator_t*xl = NULL;
	void * tmp = NULL;
	int ret = -1;

	UNIFY_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);
	
	ret = dict_get_ptr (priv->xl_array, loc->object->lhost, &tmp);
	if( ret != 0 ){
		gf_log (this->name, GF_LOG_ERROR, "unify can't find right child xlator");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
		
	}

	xl = (xlator_t *)tmp;
	//gf_log (this->name, GF_LOG_DEBUG, "unify will send stat to xlator:%s object %s",xl->name, loc->path);
	
	STACK_WIND (frame, unify_stat_cbk, xl, xl->fops->stat, loc);
	return 0;
}



/**
 * notify
 */
int32_t
notify (xlator_t *this,
        int32_t event,
        void *data,
        ...)
{
	uint32_t i = 0;
	xlator_t *trav = NULL;
	xlator_t *child = (xlator_t *)data;

	unify_private_t *priv = this->private;
	
	if (!priv) {
		return 0;
	}

	trav = this->children;
	/* Get the number of child count */
	while (trav) {
		if(trav == child)
			break;
		i++;
		trav = trav->next;
	}
	switch (event)
	{
		case GF_EVENT_CHILD_UP:
		{
			LOCK (&priv->lock);
			{
				/* Increment the inode's generation, which is 
				   used for self_heal */
				++priv->num_child_up;
				priv->child_status[i] = 1;
			}
			UNLOCK (&priv->lock);


			if (!priv->is_up) {
				default_notify (this, event, data);
				priv->is_up = 1;
			}
		}
		break;
		case GF_EVENT_CHILD_DOWN:
		{
			LOCK (&priv->lock);
			{
				--priv->num_child_up;
				priv->child_status[i] = 0;
			}
			UNLOCK (&priv->lock);

			if (priv->num_child_up == 0) {
				/* Send CHILD_DOWN to upper layer */
				default_notify (this, event, data);
				priv->is_up = 0;
			}
		}
		break;

		default:
		{
			default_notify (this, event, data);
		}
		break;
	}

	return 0;
}

/** 
 * init - This function is called first in the xlator, while initializing.
 *   All the config file options are checked and appropriate flags are set.
 *
 * @this - 
 */
int32_t 
init (xlator_t *this)
{
	int32_t          count     = 0;
	int32_t 	 i	   = 0;
	xlator_list_t   *trav      = NULL;
	data_t		*data	   = NULL;
	unify_private_t *_private  = NULL; 
	char 		*hostname = NULL;
	data_t 		*remote_host = NULL;
	data_t          *local_address = NULL;
	

	/* Check for number of child nodes, if there is no child nodes, exit */
	if (!this->children) {
		gf_log (this->name, GF_LOG_ERROR,
			"No child nodes specified. check \"subvolumes \" "
			"option in volfile");
		return -1;
	}

  	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}
	
	_private = CALLOC (1, sizeof (*_private));
	ERR_ABORT (_private);
	
	/* update _private structure */
	{
		count = 0;
		trav = this->children;
		/* Get the number of child count */
		while (trav) {
			count++;
			trav = trav->next;
		}
		
		gf_log (this->name, GF_LOG_DEBUG, 
			"Child node count is %d", count);    

		_private->child_count = count;
		if (count == 1) {
			/* TODO: Should I error out here? */
			gf_log (this->name, GF_LOG_CRITICAL, 
				"WARNING: You have defined only one "
				"\"subvolumes\" for unify volume. It may not "
				"be the desired config, review your volume "
				"volfile. If this is how you are testing it,"
				" you may hit some performance penalty");
		}
		_private->child_status = CALLOC (count, sizeof(char));
		if(_private->child_status == NULL) {
			gf_log (this->name, GF_LOG_ERROR, "Out of memory");
			return -1;
		}
		for(i = 0; i <  count; i++) {
			_private->child_status[i] = 0;
		}


		_private->xl_array = dict_new ();
		ERR_ABORT (_private->xl_array);
		
		trav = this->parents;
		while (trav) {
			local_address = dict_get (trav->xlator->options, "local-address");
			if(local_address == NULL) 
				continue;
			else
				break;
		}
		if(local_address == NULL) 
			return -1;

		gf_log (this->name, GF_LOG_TRACE, "local address resovled success %s\n", local_address->data);
		
		trav = this->children;
		if(trav)
		{
			dict_set_ptr (_private->xl_array, data_to_str(local_address), (void *)(trav->xlator)); //local_brick
			trav = trav->next;
		}
		
		while (trav) {			
			dict_set_ptr (_private->xl_array, trav->xlator->name, (void *)(trav->xlator));
			trav = trav->next;
		}


		LOCK_INIT (&_private->lock);
	}

	/* Now that everything is fine. */
	this->private = (void *)_private;

	FREE(hostname);

	return 0;
}

/** 
 * fini  - Free all the allocated memory 
 */
void
fini (xlator_t *this)
{
	unify_private_t *priv = this->private;
	this->private = NULL;
	LOCK_DESTROY (&priv->lock);

	FREE (priv->child_status);
	FREE (priv->xl_array);
	FREE (priv);
	return;
}


struct xlator_fops fops = {
	.open        = unify_open,
	.readv	     = unify_readv,
	.writev      = unify_writev,
	.unlink      = unify_unlink,
	.stat        = unify_stat,
	.fstat       = unify_fstat,
	.flush	     = unify_flush,
	.ioctl	     = unify_ioctl,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = { "local-brick" },  
	  .type  = GF_OPTION_TYPE_XLATOR 
	},
	{ .key   = { "local-address" },  
	  .type  = GF_OPTION_TYPE_STR
	},
	{ .key   = {NULL} },
};
