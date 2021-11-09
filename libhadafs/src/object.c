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

#include "object.h"
#include "common-utils.h"
#include <pthread.h>
#include <sys/types.h>
#include <stdint.h>
#include "list.h"
#include <time.h>
#include <assert.h>

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

static object_t *
__object_unref (object_t *object);

static int
hash_path (char *path,
           int mod)
{
	char *index = NULL;
        unsigned int hash = 0;
        int ret = 0;

	index = path;
        hash = *path;
        if (hash) {
                for (index += 1; *index != '\0'; index++) {
                        hash = (hash << 5) - hash + *index;
                }
        }
        ret = hash % mod;

        return ret;
}

static void
__object_unhash (object_t *object)
{
        list_del_init (&object->hash);
}


static int
__is_object_hashed (object_t *object)
{
        return !list_empty (&object->hash);
}


static void
__object_hash (object_t *object)
{
        object_table_t *table = NULL;
        int            hash = 0;

        table = object->table;
        hash = hash_path (object->path, table->hashsize);

        list_del_init (&object->hash);
        list_add (&object->hash, &table->object_hash[hash]);
	table->object_count ++;
}


static object_t *
__object_search (object_table_t *table,
                const char *path)
{
        int  hash = 0;
        object_t  *object = NULL;
        object_t  *tmp = NULL;

        hash = hash_path (path, table->hashsize);
	
        list_for_each_entry (tmp, &table->object_hash[hash], hash) {
                if (!strcasecmp(tmp->path, path)) {
                        object = tmp;
                        break;
                }
        }

        return object;
}

int
object_link (object_t *object)
{
        object_table_t *table = NULL;

        table = object->table;

        pthread_mutex_lock (&table->lock);
        {
                __object_hash (object);
        }
        pthread_mutex_unlock (&table->lock);

        return 0;
}

static object_t*
__object_unlink(object_t *object)
{
	object_table_t *table = NULL;
	table = object->table;

	table->object_count --;
	__object_unhash(object);

	return object;
}

int
object_unlink(object_t * object)
{
	object_table_t *table = NULL;
	table = object->table;
	pthread_mutex_lock(&table->lock);
	{
		object = __object_unlink(object);
	}
	pthread_mutex_unlock(&table->lock);

	return 0;
}
	

static void
__object_destroy (object_t *object)
{
	int          index = 0;
        xlator_t    *xl = NULL;

	if (!object->_ctx)
		goto noctx;

	for (index = 0; index < object->table->xl->ctx->xl_count; index++) {
		if (object->_ctx[index].key) {
			xl = (xlator_t *)(long)object->_ctx[index].key;
			if (xl->cbks->forget)
				xl->cbks->forget (xl, object);
		}
	}	

	FREE (object->_ctx);
        if(object->path)
	   	free(object->path);
        if(object->ppath)
	   	free(object->ppath);
	if(object->sid)
		free(object->sid);
	if(object->vmp)
		free(object->vmp);
noctx:
        LOCK_DESTROY (&object->lock);

        FREE (object);
}


static object_t *
__object_unref (object_t *object)
{
        assert (object->ref);

        --object->ref;

        if (!object->ref) {
		__object_unlink(object);
                __object_destroy (object);
        }

        return object;
}

static object_t *
__object_ref (object_t *object)
{
        object->ref++;
        return object;
}


object_t *
object_unref (object_t *object)
{
        object_table_t *table = NULL;

        table = object->table;

        pthread_mutex_lock (&table->lock);
        {
                object = __object_unref (object);
        }
        pthread_mutex_unlock (&table->lock);

        return object;
}


object_t *
object_ref (object_t *object)
{
        object_table_t *table = NULL;

        table = object->table;

        pthread_mutex_lock (&table->lock);
        {
                object = __object_ref (object);
        }
        pthread_mutex_unlock (&table->lock);

        return object;
}

static object_t *
__object_create (object_table_t *table, char *path, char *sid, uint32_t soffset)
{
        object_t  *newo = NULL;

        newo = (void *) CALLOC (1, sizeof (*newo));
        if (!newo)
                return NULL;

        newo->table = table;

        LOCK_INIT (&newo->lock);

        INIT_LIST_HEAD (&newo->fd_list);
        INIT_LIST_HEAD (&newo->hash);

	newo->_ctx = CALLOC (1, (sizeof (struct _object_ctx) * 
				 table->xl->ctx->xl_count));

	newo->ctx = get_new_dict ();
	newo->path = strdup(path);
	if(sid != NULL) {
		newo->sid = strdup(sid);
		newo->soffset = soffset;
	}
	newo->location = OBJ_NEWCREATED;

        return newo;
}


object_t *
object_new (object_table_t *table, char *path, char *sid, uint32_t soffset)
{
        object_t *object = NULL;

        pthread_mutex_lock (&table->lock);
        {
                object = __object_create (table, path, sid, soffset);
                __object_ref (object);
        }
        pthread_mutex_unlock (&table->lock);

        return object;
}

object_t *
object_search (object_table_t *table,
              const char *path)
{
        object_t *object = NULL;
		
        pthread_mutex_lock (&table->lock);
        {
                object = __object_search (table, path);
		if(object != NULL)
			__object_ref (object);
        }
        pthread_mutex_unlock (&table->lock);

        return object;
}

object_table_t *
object_table_new (size_t lru_limit, xlator_t *xl)
{
        object_table_t *new = NULL;
        int            i = 0;


        new = (void *)calloc (1, sizeof (*new));
        if (!new)
                return NULL;

        new->xl = xl;

        new->lru_limit = lru_limit;
	new->object_count = 0;

        new->hashsize = 14057; /* TODO: Random Number?? */

        new->object_hash = (void *)calloc (new->hashsize,
                                          sizeof (struct list_head));
        if (!new->object_hash) {
                FREE (new);
                return NULL;
        }

        for (i=0; i<new->hashsize; i++) {
                INIT_LIST_HEAD (&new->object_hash[i]);
        }


        asprintf (&new->name, "%s/object", xl->name);

        pthread_mutex_init (&new->lock, NULL);

        return new;
}

int
__object_ctx_put (object_t *object, xlator_t *xlator, uint64_t value)
{
        int ret = 0;
        int index = 0;
        int put_idx = -1;

        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (!object->_ctx[index].key) {
                        if (put_idx == -1)
                                put_idx = index;
                        /* dont break, to check if key already exists
                           further on */
                }
                if (object->_ctx[index].key == (uint64_t)(long) xlator) {
                        put_idx = index;
                        break;
                }
        }
	
        if (put_idx == -1) {
                ret = -1;
                goto out;;
        }

        object->_ctx[put_idx].key   = (uint64_t)(long) xlator;
        object->_ctx[put_idx].value = value;
out:
        return ret;
}

int
object_ctx_put (object_t *object, xlator_t *xlator, uint64_t value)
{
        int ret = 0;

	if (!object || !xlator)
		return -1;

        LOCK (&object->lock);
        {
                ret = __object_ctx_put (object, xlator, value);
        }
        UNLOCK (&object->lock);

	return ret;
}

int
__object_ctx_get (object_t *object, xlator_t *xlator, uint64_t *value)
{
	int index = 0;
        int ret = 0;
        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (object->_ctx[index].key == (uint64_t)(long)xlator)
                        break;
        }

        if (index == xlator->ctx->xl_count) {
                ret = -1;
                goto out;
        }

        if (value) 
                *value = object->_ctx[index].value;

out:
        return ret;
}

int 
object_ctx_get (object_t *object, xlator_t *xlator, uint64_t *value)
{
        int ret = 0;

	if (!object || !xlator)
		return -1;

        LOCK (&object->lock);
        {
                ret = __object_ctx_get (object, xlator, value);
        }
        UNLOCK (&object->lock);

	return ret;
}


int 
object_ctx_del (object_t *object, xlator_t *xlator, uint64_t *value)
{
	int index = 0;
        int ret = 0;

	if (!object || !xlator)
		return -1;

        LOCK (&object->lock);
        {
                for (index = 0; index < xlator->ctx->xl_count; index++) {
                        if (object->_ctx[index].key == (uint64_t)(long)xlator)
                                break;
                }

                if (index == xlator->ctx->xl_count) {
                        ret = -1;
                        goto unlock;
                }

                if (value)
                        *value = object->_ctx[index].value;		

                object->_ctx[index].key   = 0;
                object->_ctx[index].value = 0;
        }
unlock:
        UNLOCK (&object->lock);

	return ret;
}
