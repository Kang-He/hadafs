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

#include "fd.h"
#include "hadafs.h"
#include "object.h"
#include "dict.h"


#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif


static uint32_t 
gf_fd_fdtable_expand (fdtable_t *fdtable, uint32_t nr);

static fd_t *
_fd_ref (fd_t *fd);

/* 
   Allocate in memory chunks of power of 2 starting from 1024B 
   Assumes fdtable->lock is held
*/
static inline uint32_t 
gf_roundup_power_of_two (uint32_t nr)
{
        uint32_t result = 1;

        if (nr < 0) {
                gf_log ("server-protocol/fd",
                                GF_LOG_ERROR,
                                "Negative number passed");
                return -1;
        }

        while (result <= nr)
                result *= 2;

        return result;
}

static int
gf_fd_chain_fd_entries (fdentry_t *entries, uint32_t startidx,
                        uint32_t endcount)
{
        uint32_t        i = 0;

        if (!entries)
                return -1;

        /* Chain only till the second to last entry because we want to
         * ensure that the last entry has GF_FDTABLE_END.
         */
        for (i = startidx; i < (endcount - 1); i++)
                entries[i].next_free = i + 1;

        /* i has already been incremented upto the last entry. */
        entries[i].next_free = GF_FDTABLE_END;

        return 0;
}


static uint32_t 
gf_fd_fdtable_expand (fdtable_t *fdtable, uint32_t nr)
{
	fdentry_t *oldfds = NULL;
	uint32_t oldmax_fds = -1;
  
	if (fdtable == NULL || nr < 0)
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		return EINVAL;
	}
  
	nr /= (1024 / sizeof (fdentry_t));
	nr = gf_roundup_power_of_two (nr + 1);
	nr *= (1024 / sizeof (fdentry_t));

	oldfds = fdtable->fdentries;
	oldmax_fds = fdtable->max_fds;

	fdtable->fdentries = CALLOC (nr, sizeof (fdentry_t));
	ERR_ABORT (fdtable->fdentries);
	fdtable->max_fds = nr; 

	if (oldfds) {
		uint32_t cpy = oldmax_fds * sizeof (fdentry_t);
		memcpy (fdtable->fdentries, oldfds, cpy);
	}

        gf_fd_chain_fd_entries (fdtable->fdentries, oldmax_fds,
                                fdtable->max_fds);

        /* Now that expansion is done, we must update the fd list
         * head pointer so that the fd allocation functions can continue
         * using the expanded table.
         */
        fdtable->first_free = oldmax_fds;
	gf_log ("fdtable", GF_LOG_DEBUG, "fdtable{%p} dentries %d first_free %d", fdtable, fdtable->max_fds, oldmax_fds);
	FREE (oldfds);
	return 0;
}

fdtable_t *
gf_fd_fdtable_alloc (void) 
{
	fdtable_t *fdtable = NULL;

	fdtable = CALLOC (1, sizeof (*fdtable));
	if (!fdtable) 
		return NULL;

	pthread_mutex_init (&fdtable->lock, NULL);

	fdtable->max_fds = 0;
	pthread_mutex_lock (&fdtable->lock);
	{
		gf_fd_fdtable_expand (fdtable, 0);
	}
	pthread_mutex_unlock (&fdtable->lock);

	return fdtable;
}

fdentry_t *
__gf_fd_fdtable_get_all_fds (fdtable_t *fdtable, uint32_t *count)
{
        fdentry_t       *fdentries = NULL;

        if (count == NULL) {
                goto out;
        }

        fdentries = fdtable->fdentries;
        fdtable->fdentries = calloc (fdtable->max_fds, sizeof (fdentry_t));
        gf_fd_chain_fd_entries (fdtable->fdentries, 0, fdtable->max_fds);
        *count = fdtable->max_fds;

out:
        return fdentries;
}

fdentry_t *
gf_fd_fdtable_get_all_fds (fdtable_t *fdtable, uint32_t *count)
{
        fdentry_t       *entries = NULL;
        if (fdtable) {
                pthread_mutex_lock (&fdtable->lock);
                {
                        entries = __gf_fd_fdtable_get_all_fds (fdtable, count);
                }
                pthread_mutex_unlock (&fdtable->lock);
        }

        return entries;
}

void 
gf_fd_fdtable_destroy (fdtable_t *fdtable)
{
        struct list_head  list = {0, };
        fd_t             *fd = NULL;
        fdentry_t        *fdentries = NULL;
        uint32_t          fd_count = 0;
        int32_t           i = 0; 

        INIT_LIST_HEAD (&list);

	if (!fdtable)
                return;

	pthread_mutex_lock (&fdtable->lock);
	{
                fdentries = __gf_fd_fdtable_get_all_fds (fdtable, &fd_count);
		FREE (fdtable->fdentries);
	}
	pthread_mutex_unlock (&fdtable->lock);

        if (fdentries != NULL) {
                for (i = 0; i < fd_count; i++) {
                        fd = fdentries[i].fd;
                        if (fd != NULL) {
                                fd_unref (fd);
                        }
                }

                FREE (fdentries);
		pthread_mutex_destroy (&fdtable->lock);
		FREE (fdtable);
	}
}

int32_t 
gf_fd_unused_get (fdtable_t *fdtable, fd_t *fdptr)
{
	int32_t         fd = -1;
        fdentry_t       *fde = NULL;
	int             error;
        int             alloc_attempts = 0;
  
	if (fdtable == NULL || fdptr == NULL)
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		return EINVAL;
	}
  
	pthread_mutex_lock (&fdtable->lock);
	{
fd_alloc_try_again:
                if (fdtable->first_free != GF_FDTABLE_END) {
                        fde = &fdtable->fdentries[fdtable->first_free];
                        fd = fdtable->first_free;
                        fdtable->first_free = fde->next_free;
			fde->next_free = GF_FDENTRY_ALLOCATED;
			fde->fd = fdptr;
			//urgly, for debug
			fde->path = fdptr->object->path;
			if(strcmp(fdtable->fdentries[fd].path, fdptr->object->path))
				gf_log ("fd", GF_LOG_ERROR, "fd_unused_get fd %s bad fd %p, object %s", 
						fdtable->fdentries[fd].path, fdptr, fdptr->object->path);
		} else {
                        /* If this is true, there is something
                         * seriously wrong with our data structures.
                         */
                        if (alloc_attempts >= 2) {
                                gf_log ("server-protocol.c", GF_LOG_ERROR,
                                        "Multiple attempts to expand fd table"
                                        " have failed.");
                                goto out;
                        }
                        error = gf_fd_fdtable_expand (fdtable,
                                                      fdtable->max_fds + 1);
			if (error) {
				gf_log ("server-protocol.c",
					GF_LOG_ERROR,
					"Cannot expand fdtable:%s", strerror (error));
                                goto out;
			}
                        ++alloc_attempts;
                        /* At this point, the table stands expanded
                         * with the first_free referring to the first
                         * free entry in the new set of fdentries that
                         * have just been allocated. That means, the
                         * above logic should just work.
                         */
                        goto fd_alloc_try_again;
		}
	}
out:
	pthread_mutex_unlock (&fdtable->lock);

	return fd;
}


inline void 
gf_fd_put (fdtable_t *fdtable, int32_t fd)
{
	fd_t *fdptr = NULL;
        fdentry_t *fde = NULL;

	if (fdtable == NULL || fd < 0)
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		return;
	}
  
	if (!(fd < fdtable->max_fds))
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		return;
	}

	pthread_mutex_lock (&fdtable->lock);
	{
                fde = &fdtable->fdentries[fd];
                /* If the entry is not allocated, put operation must return
                 * without doing anything.
                 * This has the potential of masking out any bugs in a user of
                 * fd that ends up calling gf_fd_put twice for the same fd or
                 * for an unallocated fd, but thats a price we have to pay for
                 * ensuring sanity of our fd-table.
                 */

                if (fde->next_free != GF_FDENTRY_ALLOCATED)
                        goto unlock_out;
                fdptr = fde->fd;
                fde->fd = NULL;
                fde->next_free = fdtable->first_free;
                fdtable->first_free = fd;
		//urgly, for debug
		if(strcmp(fdtable->fdentries[fd].path, fdptr->object->path))
			gf_log ("fd", GF_LOG_ERROR, "fd_put fd %s bad fd %p, object %s", 
				fdtable->fdentries[fd].path, fdptr, fdptr->object->path);
	}
unlock_out:
	pthread_mutex_unlock (&fdtable->lock);

	if (fdptr) {
		fd_unref (fdptr);
	}
}


fd_t *
gf_fd_fdptr_get (fdtable_t *fdtable, int64_t fd)
{
	fd_t *fdptr = NULL;
  
	if (fdtable == NULL || fd < 0)
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		errno = EINVAL;
		return NULL;
	}
  
	if (!(fd < fdtable->max_fds))
	{
		gf_log ("fd", GF_LOG_ERROR, "invalid argument");
		errno = EINVAL;
		return NULL;
	}

	pthread_mutex_lock (&fdtable->lock);
	{
		fdptr = fdtable->fdentries[fd].fd;
		if (fdptr) {
			fd_ref (fdptr);
			//urgly, for debug
			if(strcmp(fdtable->fdentries[fd].path, fdptr->object->path))
				gf_log ("fd", GF_LOG_ERROR, "fd_get fd %s bad fd %p, object %s", 
						fdtable->fdentries[fd].path, fdptr, fdptr->object->path);
		}
	}
	pthread_mutex_unlock (&fdtable->lock);

	return fdptr;
}

fd_t *
_fd_ref (fd_t *fd)
{
	//gf_log_dump_backtrace(fd->object->path);
	++fd->refcount;
	
	return fd;
}

fd_t *
fd_ref (fd_t *fd)
{
	fd_t *refed_fd = NULL;

	if (!fd) {
		gf_log ("fd", GF_LOG_ERROR, "@fd=%p", fd);
		return NULL;
	}
	if(!fd->object) {
		gf_log ("fd", GF_LOG_ERROR, "@fd->objecct=%p", fd->object);
		return NULL;
	}
	LOCK (&fd->object->lock);
	refed_fd = _fd_ref (fd);
	UNLOCK (&fd->object->lock);
	
	return refed_fd;
}

fd_t *
_fd_unref (fd_t *fd)
{
	//gf_log_dump_backtrace(fd->object->path);
	assert (fd->refcount);

	--fd->refcount;

	if (fd->refcount == 0){
		list_del_init (&fd->object_list);
	}
	
	return fd;
}

static void
fd_destroy (fd_t *fd)
{
        xlator_t    *xl = NULL;
	int i = 0;

        if (fd == NULL){
                gf_log ("fd", GF_LOG_ERROR, "invalid arugument");
                goto out;
        }
  
        if (fd->object == NULL){
                gf_log ("fd", GF_LOG_ERROR, "fd->object is NULL");
                goto out;
        }

	if (!fd->_ctx)
		goto out;

	for (i = 0; i < fd->object->table->xl->ctx->xl_count; i++) {
		if (fd->_ctx[i].key) {
			xl = (xlator_t *)(long)fd->_ctx[i].key;
			if (xl->cbks->release) {
				gf_log ("fd-destory", GF_LOG_TRACE, "release by %s",
					xl->name);
				xl->cbks->release (xl, fd);
			}
		}
	}
        
        LOCK_DESTROY (&fd->lock);

	FREE (fd->_ctx);
        object_unref (fd->object);
        fd->object = (object_t *)0xaaaaaaaa;
        FREE (fd);
        
out:
        return;
}

void
fd_unref (fd_t *fd)
{
        int32_t refcount = 0;

        if (!fd) {
                gf_log ("fd.c", GF_LOG_ERROR, "fd is NULL");
                return;
        }
        
        LOCK (&fd->object->lock);
        {
                _fd_unref (fd);
                refcount = fd->refcount;
        }
        UNLOCK (&fd->object->lock);
        
        if (refcount == 0) {
                fd_destroy (fd);
        }

        return ;
}

fd_t *
fd_bind (fd_t *fd)
{
        object_t *object = fd->object;

        if (!fd) {
                gf_log ("fd.c", GF_LOG_ERROR, "fd is NULL");
                return NULL;
        }

        LOCK (&object->lock);
        {
                list_add (&fd->object_list, &object->fd_list);
        }
        UNLOCK (&object->lock);
        
        return fd;
}

fd_t *
fd_create (object_t *object, pid_t pid)
{
        fd_t *fd = NULL;
  
        if (object == NULL) {
                gf_log ("fd", GF_LOG_ERROR, "invalid argument");
                return NULL;
        }
  
        fd = CALLOC (1, sizeof (fd_t));
        ERR_ABORT (fd);
  
	fd->_ctx = CALLOC (1, (sizeof (struct _fd_ctx) * 
			       object->table->xl->ctx->xl_count));
        fd->object = object_ref (object);
        fd->pid = pid;
        INIT_LIST_HEAD (&fd->object_list);
        
        LOCK_INIT (&fd->lock);

        LOCK (&object->lock);
        fd = _fd_ref (fd);
        UNLOCK (&object->lock);

        return fd;
}

fd_t *
fd_lookup (object_t *object, pid_t pid)
{
        fd_t *fd = NULL;
        fd_t *iter_fd = NULL;

        LOCK (&object->lock);
        {
                if (list_empty (&object->fd_list)) {
                        fd = NULL;
                } else {
                        list_for_each_entry (iter_fd, &object->fd_list, object_list) {
                                if (pid) {
                                        if (iter_fd->pid == pid) {
                                                fd = _fd_ref (iter_fd);
                                                break;
                                        }
                                } else {
                                        fd = _fd_ref (iter_fd);
                                        break;
                                }
                        }
                }
        }
        UNLOCK (&object->lock);
        
        return fd;
}

uint8_t
fd_list_empty (object_t *object)
{
        uint8_t empty = 0; 

        LOCK (&object->lock);
        {
                empty = list_empty (&object->fd_list);
        }
        UNLOCK (&object->lock);
        
        return empty;
}

int
__fd_ctx_set (fd_t *fd, xlator_t *xlator, uint64_t value)
{
	int index = 0;
        int ret = 0;
        int set_idx = -1;

	if (!fd || !xlator)
		return -1;
        
        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (!fd->_ctx[index].key) {
                        if (set_idx == -1)
                                set_idx = index;
                        /* dont break, to check if key already exists
                           further on */
                }
                if (fd->_ctx[index].key == (uint64_t)(long) xlator) {
                        set_idx = index;
                        break;
                }
        }
	
        if (set_idx == -1) {
                ret = -1;
                goto out;
        }
        
        fd->_ctx[set_idx].key   = (uint64_t)(long) xlator;
        fd->_ctx[set_idx].value = value;

out:
	return ret;
}


int
fd_ctx_set (fd_t *fd, xlator_t *xlator, uint64_t value)
{
        int ret = 0;

	if (!fd || !xlator)
		return -1;
        
        LOCK (&fd->lock);
        {
                ret = __fd_ctx_set (fd, xlator, value);
        }
        UNLOCK (&fd->lock);

        return ret;
}


int 
__fd_ctx_get (fd_t *fd, xlator_t *xlator, uint64_t *value)
{
	int index = 0;
        int ret = 0;

	if (!fd || !xlator)
		return -1;
        
        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (fd->_ctx[index].key == (uint64_t)(long)xlator)
                        break;
        }
        
        if (index == xlator->ctx->xl_count) {
                ret = -1;
                goto out;
        }

        if (value) 
                *value = fd->_ctx[index].value;
        
out:
	return ret;
}


int 
fd_ctx_get (fd_t *fd, xlator_t *xlator, uint64_t *value)
{
        int ret = 0;

	if (!fd || !xlator)
		return -1;

        LOCK (&fd->lock);
        {
                ret = __fd_ctx_get (fd, xlator, value);
        }
        UNLOCK (&fd->lock);

        return ret;
}


int 
__fd_ctx_del (fd_t *fd, xlator_t *xlator, uint64_t *value)
{
	int index = 0;
        int ret = 0;

	if (!fd || !xlator)
		return -1;
        
        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (fd->_ctx[index].key == (uint64_t)(long)xlator)
                        break;
        }
        
        if (index == xlator->ctx->xl_count) {
                ret = -1;
                goto out;
        }
        
        if (value) 
                *value = fd->_ctx[index].value;		
        
        fd->_ctx[index].key   = 0;
        fd->_ctx[index].value = 0;

out:
	return ret;
}


int 
fd_ctx_del (fd_t *fd, xlator_t *xlator, uint64_t *value)
{
        int ret = 0;

	if (!fd || !xlator)
		return -1;
        
        LOCK (&fd->lock);
        {
                ret = __fd_ctx_del (fd, xlator, value);
        }
        UNLOCK (&fd->lock);

        return ret;
}
