/*
  Copyright (c) 2006-2009 Gluster, Inc. <http://www.gluster.com>
  This file is part of GlusterFS.

  GlusterFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  GlusterFS is distributed in the hope that it will be useful, but
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

#include "call-stub.h"
#include "hadafs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "io-threads.h"
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "locking.h"
#include <string.h>
#include "qos.h"
#include "redis_subscriber.h"

//QoS
void
_iot_qos_queue_with_stub (iot_worker_t *worker, call_stub_t *stub);

void
_iot_queue_with_stub (iot_worker_t *worker, call_stub_t *stub);

void
_iot_qos_queue (iot_worker_t *worker, iot_request_t *req);




typedef void *(*iot_worker_fn)(void*);

void
iot_stop_worker (iot_worker_t *worker);

void
iot_stop_workers (iot_worker_t **workers, int start_idx, int count);

void
_iot_queue (iot_worker_t *worker, iot_request_t *req);

iot_request_t *
iot_init_request (iot_worker_t *conf, call_stub_t *stub);

int
iot_startup_workers (iot_worker_t **workers, int start_idx, int count,
                     iot_worker_fn workerfunc);

void *
iot_worker_unordered (void *arg);

void *
iot_worker_ordered (void *arg);

int
iot_startup_worker (iot_worker_t *worker, iot_worker_fn workerfunc);

void
iot_destroy_request (iot_worker_t *worker, iot_request_t * req);

void
iot_notify_worker (iot_worker_t *worker)
{
#ifndef HAVE_SPINLOCK
        pthread_cond_broadcast (&worker->notifier);
#else
        sem_post (&worker->notifier);
#endif

        return;
}

int
iot_notify_wait (iot_worker_t *worker, int idletime)
{
        struct timeval  tv;
        struct timespec ts = {0, };
        int             waitres = 0;

        gettimeofday (&tv, NULL);
        /* Slightly skew the idle time for threads so that, we dont
         * have all of them rushing to exit at the same time, if
         * they've been idle.
         */
        ts.tv_sec = skew_sec_idle_time (tv.tv_sec + idletime);

#ifndef HAVE_SPINLOCK
        waitres = pthread_cond_timedwait (&worker->notifier, &worker->qlock,
                                          &ts);
#else
        UNLOCK (&worker->qlock);
        errno = 0;
        waitres = sem_timedwait (&worker->notifier, &ts);
        LOCK (&worker->qlock);
        if (waitres < 0)
                waitres = errno;
#endif

        return waitres;
}

void
iot_notify_init (iot_worker_t *worker)
{
        if (worker == NULL)
                return;

        LOCK_INIT (&worker->qlock);

#ifndef HAVE_SPINLOCK
        pthread_cond_init (&worker->notifier, NULL);
#else
        sem_init (&worker->notifier, 0, 0);
#endif



        return;
}

/* I know this function modularizes things a bit too much,
 * but it is easier on the eyes to read this than see all that locking,
 * queueing, and thread firing in the same curly block, as was the
 * case before this function.
 */
int
iot_request_queue_and_thread_fire (iot_worker_t *worker,
                                   iot_worker_fn workerfunc, iot_request_t *req)
{
        int     ret = -1; 
        LOCK (&worker->qlock);
        {
                if (iot_worker_active (worker)) {
					//QoS
					//if(req->stub->app != NULL && worker->queue_size > 0)
					//	_iot_qos_queue (worker, req);
					//else
                    //    _iot_queue (worker, req);

						_iot_queue (worker, req);
                        ret = 0;
                }else {
                        ret = iot_startup_worker (worker, workerfunc);
                        if (ret < 0) {
                                goto unlock;
                        }
					//QoS
					//if(req->stub->app != NULL && worker->queue_size > 0)
					//	_iot_qos_queue (worker, req);
					//else
					//	_iot_queue (worker, req);
						
                        _iot_queue (worker, req);
                }
        }
unlock:
        UNLOCK (&worker->qlock);

		//Qos

        return ret;
}

//QoS
//use stub instead of req
int
iot_request_queue_and_thread_fire_with_stub (iot_worker_t *worker,
                                   iot_worker_fn workerfunc, call_stub_t *stub)
{
        int     ret = -1; 

        LOCK (&worker->qlock);
        {
                if (iot_worker_active (worker)) {
					//QoS
					if(stub->app != NULL && worker->queue_size > 0)
						_iot_qos_queue_with_stub (worker, stub);
					else
                        _iot_queue_with_stub (worker, stub);
                        ret = 0;
                }else {
                        ret = iot_startup_worker (worker, workerfunc);
                        if (ret < 0) {
                                goto unlock;
                        }
					//QoS
					if(stub->app != NULL && worker->queue_size > 0)
						_iot_qos_queue_with_stub (worker, stub);
					else
						_iot_queue_with_stub (worker, stub);
                }
        }
unlock:
        UNLOCK (&worker->qlock);


        return ret;
}


int
iot_unordered_request_balancer (iot_conf_t *conf)
{
        long int        rand = 0;
        int             idx = 0;

        /* Decide which thread will service the request.
         * FIXME: This should change into some form of load-balancing.
         * */
        rand = random ();

        /* If scaling is on, we can choose from any thread
        * that has been allocated upto, max_o_threads, but
        * with scaling off, we'll never have threads more
        * than min_o_threads.
        */
        if (iot_unordered_scaling_on (conf))
                idx = (rand % conf->max_u_threads);
        else
                idx = (rand % conf->min_u_threads);

        return idx;
}


int
iot_schedule_unordered (iot_conf_t *conf, call_stub_t *stub)
{
        int32_t          idx = 0;
        iot_worker_t    *selected_worker = NULL;
        iot_request_t   *req = NULL;
        int             ret = -1;

        idx = iot_unordered_request_balancer (conf);
        selected_worker = conf->uworkers[idx];

        req = iot_init_request (selected_worker, stub);
        if (req == NULL) {
                ret = -ENOMEM;
                goto out;
        }

        ret = iot_request_queue_and_thread_fire (selected_worker,
                                                 iot_worker_unordered, req);
        if (ret < 0) {
                iot_destroy_request (selected_worker, req);
        }
out:
        return ret;
}



/*
* Replace worker queue with global conf queue
*/
int
iot_schedule_ordered (iot_conf_t *conf, call_stub_t *stub)
{
    int ret = 0;
	if(stub->app == NULL)
		pthread_mutex_lock(&conf->otlock);

	{
		//QoS priority queue
		if(stub->reserve_flag == _gf_false && stub->app != NULL){
			APP_Qos_Info *app = (APP_Qos_Info *)stub->app;
			
			list_add_tail(&stub->list, &conf->priority_req);
			
			//gf_log(conf->this->name, GF_LOG_ERROR, "jy_message:app %s  priority_enqueue", app->uuid);
		}
		else{
			APP_Qos_Info *app = (APP_Qos_Info *)stub->app;
			
			list_add_tail(&stub->list, &conf->normal_req);
			//gf_log(conf->this->name, GF_LOG_ERROR, "jy_message:app %s  normal_enqueue", app->uuid);
		}

		pthread_cond_broadcast (&conf->ot_notifier);
	}

	if(stub->app == NULL)
		pthread_mutex_unlock(&conf->otlock);
	
    return ret;
}


int
iot_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iovec *vector,
               int32_t count, struct stat *stbuf, struct iobref *iobref)
{
	STACK_UNWIND (frame, op_ret, op_errno, vector, count,
                             stbuf, iobref);

	return 0;
}


int
iot_readv_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                   off_t offset)
{
	STACK_WIND (frame, iot_readv_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readv,
		    fd, size, offset);
	return 0;
}


int
iot_readv (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
           off_t offset)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_readv_stub (frame, iot_readv_wrapper, fd, size, offset);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR, 
			"cannot create readv call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}
    //QoS
    //call_stack_t *root = frame->root;
    client_id_t *client = (client_id_t*) frame->root->trans;
    //gf_log(this->name, GF_LOG_ERROR, "jy_message:size of req:%d, count:%d", vector[0].iov_len, count);
    //gf_log(this->name, GF_LOG_ERROR, "jy_message:req from client: %s", client->id);

	iot_conf_t *conf = (iot_conf_t *)this->private;
	APP_Qos_Info *app = NULL;
	int limit_flag = _gf_true;
    char uuid[MAX_APP_IDENTIFY];
	pthread_mutex_lock(&conf->otlock);
	{
		//get pp
        iot_qos_get_uuid(client->id,uuid);
		app = iot_qos_client_exist(uuid, conf);
		if(app == NULL){
			//gf_log(this->name, GF_LOG_ERROR, "jy_message:req from new client: %s", client->id);
			double reserve;
			double limit;
			int IS_IOPS = 0;
			double block_size = size;
            //gf_log(this->name, GF_LOG_ERROR, "#mydebug block_size=%lf",block_size);
			//for bandwidth, 100 means 100 MB/s;
			//for IOPS, 100 means 100 IO/s, block_size = X Byte
			//so bandwidth = IOPS * block_size / (1024 * 1024);
			
			reserve = conf->default_reserve;
			limit=conf->default_limit;
			/*if(block_size > (16*1024))
				conf->default_BW = conf->BW_BIG;
			else
				conf->default_BW = conf->BW_SMALL;
			*/
			/*if(conf->app_count % 5 == 0){
				//IS_IOPS = 0;
				reserve = 20;
				limit = 200;
			}
			else{
				//IS_IOPS = 0;
				reserve = 20;
				limit = 200;
			}*/
			gf_log(this->name, GF_LOG_ERROR, "#mydebug app_count=%d",conf->app_count);
			
			/*if(conf->app_count==0){
				reserve=20;
				limit=300;
			}else if(conf->app_count==1){
				reserve=40;
				limit=300;
			}else if(conf->app_count==2){
				reserve=60;
				limit=300;
			}else if(conf->app_count==3){
				reserve=80;
				limit=300;
			}else if(conf->app_count==4){
				reserve=30;
				limit=1000;
			}*/
			if(IS_IOPS){
				
				reserve = reserve * (block_size / (1024 * 1024));
				limit = limit * (block_size / (1024 * 1024));
			}
			
			app = iot_qos_app_info_insert(conf, reserve, limit, client->id, IS_IOPS, block_size);
			if(app == NULL){
				gf_log(this->name, GF_LOG_ERROR, "jy_message:iot_qos_app_info_insert error!");
				pthread_mutex_unlock(&conf->otlock);
				ret = iot_schedule_ordered ((iot_conf_t *)this->private, stub);
				goto out;
			}
			else{
				stub->app = app;
				stub->limit_time = app->read_last_time;
				pthread_mutex_lock(&app->mutex);
				{
					app->req_count++;
					app->queue_size++;
					iot_qos_set_next_reserve(app, stub);
				}
				pthread_mutex_unlock(&app->mutex);
			}
		}
		else {
			if(app->state == APP_SLEEP){
				list_del_init(&app->apps);
				app->state = APP_ACTIVE;
				list_add(&app->apps, &conf->apps);
				iot_qos_app_reweight(conf);
			}
		
			stub->app = app;
			pthread_mutex_lock(&app->mutex);
			{
				app->queue_size++;
				app->req_count++;
				limit_flag = iot_qos_set_next_limit(app, stub);
				stub->reserve_flag = iot_qos_set_next_reserve(app, stub);
			}
			pthread_mutex_unlock(&app->mutex);
		}
	

		if(limit_flag == _gf_false){
			//gf_log(this->name, GF_LOG_ERROR, "jy_message:app %s reach limit", app->uuid);
			ret = 0;
			//iot_qos_notify_limit_wait(conf, stub->limit_time);
			pthread_mutex_unlock(&conf->otlock);
			pthread_mutex_lock(&conf->lworker->qlock);
			{
				if(list_empty(&conf->lworker->rqlist)){
					list_add_tail(&stub->list, &conf->lworker->rqlist);
					pthread_cond_broadcast (&conf->lworker->notifier);
				}
				else{
					list_add_tail(&stub->list, &conf->lworker->rqlist);
				}
			}
			pthread_mutex_unlock(&conf->lworker->qlock);
			goto out;
		}
		else{
        	ret = iot_schedule_ordered ((iot_conf_t *)this->private,stub);
		}

	}
	pthread_mutex_unlock(&conf->otlock);
	

    //    ret = iot_schedule_ordered ((iot_conf_t *)this->private,
    //                                stub);

out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret, NULL, -1, NULL,
                                     NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}




int
iot_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct stat *prebuf,
                struct stat *postbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, prebuf, postbuf);
	return 0;
}


int
iot_writev_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                    struct iovec *vector, int32_t count,
                    off_t offset, struct iobref *iobref)
{
	STACK_WIND (frame, iot_writev_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->writev,
		    fd, vector, count, offset, iobref);
	return 0;
}


int
iot_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
            struct iovec *vector, int32_t count, off_t offset,
            struct iobref *iobref)
{
	call_stub_t *stub = NULL;
        int         ret = -1;
	
    stub = fop_writev_stub (frame, iot_writev_wrapper,
				fd, vector, count, offset, iobref);

	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create writev call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

		

	//QoS
    //call_stack_t *root = frame->root;
    client_id_t *client = (client_id_t*) frame->root->trans;
    //gf_log(this->name, GF_LOG_ERROR, "jy_message:size of req:%d, count:%d", vector[0].iov_len, count);
    //gf_log(this->name, GF_LOG_ERROR, "jy_message:req from client: %s", client->id);

	iot_conf_t *conf = (iot_conf_t *)this->private;
	APP_Qos_Info *app = NULL;
	int limit_flag = _gf_true;
    char uuid[MAX_APP_IDENTIFY];
	pthread_mutex_lock(&conf->otlock);
	{
		//get pp
        iot_qos_get_uuid(client->id, uuid);
		app = iot_qos_client_exist(uuid, conf);
		if(app == NULL){
			//gf_log(this->name, GF_LOG_ERROR, "jy_message:req from new client: %s", client->id);
			double reserve;
			double limit;
			int IS_IOPS = 0;
			double block_size = vector[0].iov_len * count;
            //gf_log(this->name, GF_LOG_ERROR, "#mydebug block_size=%lf",block_size);
			//for bandwidth, 100 means 100 MB/s;
			//for IOPS, 100 means 100 IO/s, block_size = X Byte
			//so bandwidth = IOPS * block_size / (1024 * 1024);
		    /*if(block_size > (16*1024))
                conf->default_BW = conf->BW_BIG;
            else
                conf->default_BW = conf->BW_SMALL;
			*/	
			//gf_log(this->name, GF_LOG_ERROR, "#default_BW=%d",conf->default_BW);
			reserve = conf->default_reserve;
			limit=conf->default_limit;
			
			
			/*if(conf->app_count % 5 == 0){
				//IS_IOPS = 0;
				reserve = 20;
				limit = 200;
			}
			else{
				//IS_IOPS = 0;
				reserve = 20;
				limit = 200;
			}*/
			gf_log(this->name, GF_LOG_ERROR, "#mydebug app_count=%d",conf->app_count);
			
			/*if(conf->app_count==0){
				reserve=20;
				limit=300;
			}else if(conf->app_count==1){
				reserve=40;
				limit=300;
			}else if(conf->app_count==2){
				reserve=60;
				limit=300;
			}else if(conf->app_count==3){
				reserve=80;
				limit=300;
			}else if(conf->app_count==4){
				reserve=30;
				limit=1000;
			}*/
			if(IS_IOPS){
				
				reserve = reserve * (block_size / (1024 * 1024));
				limit = limit * (block_size / (1024 * 1024));
			}
			
			app = iot_qos_app_info_insert(conf, reserve, limit, client->id, IS_IOPS, block_size);
			if(app == NULL){
				gf_log(this->name, GF_LOG_ERROR, "jy_message:iot_qos_app_info_insert error!");
				pthread_mutex_unlock(&conf->otlock);
				ret = iot_schedule_ordered ((iot_conf_t *)this->private, stub);
				goto out;
			}
			else{
				stub->app = app;
				stub->limit_time = app->write_last_time;
				pthread_mutex_lock(&app->mutex);
				{
					app->req_count++;
					app->queue_size++;
					iot_qos_set_next_reserve(app, stub);
				}
				pthread_mutex_unlock(&app->mutex);
			}
		}
		else {
            //gf_log(this->name, GF_LOG_ERROR, "jy_message:insert app was exist");
			if(app->state == APP_SLEEP){
				list_del_init(&app->apps);
				app->state = APP_ACTIVE;
				list_add(&app->apps, &conf->apps);
				iot_qos_app_reweight(conf);
			}
		
			stub->app = app;
			pthread_mutex_lock(&app->mutex);
			{
				app->queue_size++;
				app->req_count++;
				limit_flag = iot_qos_set_next_limit(app, stub);
				stub->reserve_flag = iot_qos_set_next_reserve(app, stub);
			}
			pthread_mutex_unlock(&app->mutex);
		}
	

		if(limit_flag == _gf_false){
			//gf_log(this->name, GF_LOG_ERROR, "jy_message:app %s reach limit", app->uuid);
			ret = 0;
			//iot_qos_notify_limit_wait(conf, stub->limit_time);
			pthread_mutex_unlock(&conf->otlock);
			pthread_mutex_lock(&conf->lworker->qlock);
			{
				if(list_empty(&conf->lworker->rqlist)){
					list_add_tail(&stub->list, &conf->lworker->rqlist);
					pthread_cond_broadcast (&conf->lworker->notifier);
				}
				else{
					list_add_tail(&stub->list, &conf->lworker->rqlist);
				}
			}
			pthread_mutex_unlock(&conf->lworker->qlock);
			goto out;
		}
		else{
        	ret = iot_schedule_ordered ((iot_conf_t *)this->private,stub);
		}

	}
	pthread_mutex_unlock(&conf->otlock);
									
out:
        if (ret < 0) {
		STACK_UNWIND ( frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}

/* Must be called with worker lock held */
void
_iot_queue (iot_worker_t *worker, iot_request_t *req)
{
        list_add_tail (&req->list, &worker->rqlist);

        /* dq_cond */
        worker->queue_size++;
        iot_notify_worker(worker);
}

//QoS
//because of iot_notify_worker(worker), we can only put it here
void
_iot_qos_queue (iot_worker_t *worker, iot_request_t *req){
	int flag = _gf_true;
	struct timeval tv = req->stub->limit_time;
	iot_request_t *tmp_req;
	list_for_each_back_entry (tmp_req, &worker->rqlist, list){
		if(tmp_req->stub->app) continue;
		struct timeval tmptv = tmp_req->stub->limit_time;
		double difftime = (tv.tv_sec - tmptv.tv_sec) * 1000000.0 + tv.tv_usec - tmptv.tv_usec;
		if(difftime > 0) {
			flag = _gf_false;
			break;
		}
	}
	
	if(flag == _gf_true)
		list_add_tail (&req->list, &worker->rqlist);
	else{
		list_add (&req->list, &tmp_req->list);
	}
	
	/* dq_cond */
	worker->queue_size++;
	iot_notify_worker(worker);
}

//use stub instead of req
void
_iot_queue_with_stub (iot_worker_t *worker, call_stub_t *stub)
{
        list_add_tail (&stub->list, &worker->rqlist);

        /* dq_cond */
        worker->queue_size++;
        iot_notify_worker(worker);
}

//use stub instead of req
void
_iot_qos_queue_with_stub (iot_worker_t *worker, call_stub_t *stub){


	
	int flag = _gf_true;
	struct timeval tv = stub->reserve_time;
	call_stub_t *tmp_stub;
	
	list_for_each_back_entry (tmp_stub, &worker->rqlist, list){
		if(tmp_stub->app == NULL) continue;
		struct timeval now = tmp_stub->limit_time;
		double difftime = (tv.tv_sec - now.tv_sec) * 1000000.0 + tv.tv_usec - now.tv_usec;
		if(difftime > 0) {
			flag = _gf_false;
			break;
		}
	}
	
	if(flag == _gf_true)
		list_add (&stub->list, &worker->rqlist);
	else{
		list_add (&stub->list, &tmp_stub->list);
	}

	
	/* dq_cond */
	worker->queue_size++;
	//gf_log(conf->this->name, GF_LOG_ERROR, "jy_message: worker %d enque. queue_size:%d", worker->thread_idx, worker->queue_size);
	iot_notify_worker(worker);
}
//end QoS



iot_request_t *
iot_init_request (iot_worker_t *worker, call_stub_t *stub)
{
	iot_request_t   *req = NULL;

        req = mem_get (worker->req_pool);
        if (req == NULL) {
                goto out;
        }

        req->stub = stub;
out:
        return req;
}


void
iot_destroy_request (iot_worker_t *worker, iot_request_t * req)
{
        if ((req == NULL) || (worker == NULL))
                return;

        mem_put (worker->req_pool, req);
}


/* Must be called with worker lock held. */
gf_boolean_t
iot_can_ordered_exit (iot_worker_t * worker)
{
        gf_boolean_t     allow_exit = _gf_false;
        iot_conf_t      *conf = NULL;

        conf = worker->conf;
        /* We dont want this thread to exit if its index is
         * below the min thread count.
         */
        if (worker->thread_idx >= conf->min_o_threads)
                allow_exit = _gf_true;

        return allow_exit;
}

/* Must be called with worker lock held. */
gf_boolean_t
iot_ordered_exit (int cond_waitres, iot_worker_t *worker)
{
        gf_boolean_t     allow_exit = _gf_false;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                allow_exit = _gf_true;
        } else if (cond_waitres == ETIMEDOUT) {
                allow_exit = iot_can_ordered_exit (worker);
        }

        if (allow_exit) {
                worker->state = IOT_STATE_DEAD;
                worker->thread = 0;
        }

        return allow_exit;
}


int
iot_qos_ordered_request_wait (iot_worker_t * worker)
{
        int             waitres = 0;
        int             retstat = 0;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                retstat = -1;
                goto out;
        }

		struct timeval idletime;
		gettimeofday(&idletime,NULL);
		idletime.tv_sec += worker->conf->o_idle_time;
        waitres = iot_qos_notify_wait (worker->conf, idletime);
		
        LOCK (&worker->qlock);
        if (iot_ordered_exit (waitres, worker)) {
                retstat = -1;
        }
		UNLOCK (&worker->qlock);

out:
        return retstat;
}

int
iot_qos_lworker_wait (limit_worker *worker)
{
        int waitres = 0;
        int retstat = 0;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                retstat = -1;
                goto out;
        }

		struct timeval idletime;
		gettimeofday(&idletime,NULL);
		idletime.tv_sec += worker->conf->o_idle_time;
        waitres = iot_qos_notify_limit_wait (worker, idletime);

		if (worker->state == IOT_STATE_EXIT_REQUEST) {
            worker->state = IOT_STATE_DEAD;
            worker->thread = 0;
			retstat = -1;
        }


out:
        return retstat;
}


int
iot_ordered_request_wait (iot_worker_t * worker)
{
        int             waitres = 0;
        int             retstat = 0;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                retstat = -1;
                goto out;
        }

        waitres = iot_notify_wait (worker, worker->conf->o_idle_time);

        if (iot_ordered_exit (waitres, worker)) {
                retstat = -1;
        }

out:
        return retstat;
}



call_stub_t *
iot_dequeue_ordered (iot_worker_t *worker)
{
	call_stub_t     *stub = NULL;
	iot_request_t   *req = NULL;
        int              waitstat = 0;

	LOCK (&worker->qlock);
        {
                while (!worker->queue_size) {
                        waitstat = 0;
                        waitstat = iot_ordered_request_wait (worker);
                        /* We must've timed out and are now required to
                         * exit.
                         */
                        if (waitstat == -1)
                                goto out;
                }

                list_for_each_entry (req, &worker->rqlist, list)
                        break;
                list_del (&req->list);
                stub = req->stub;

                worker->queue_size--;

				//QoS
				//list_del_init(&stub->req);
				if(stub->app != NULL && (stub->fop == GF_FOP_WRITE || stub->fop == GF_FOP_READ)){
					if(iot_qos_is_over_limit_time(stub->limit_time) == _gf_false){
						//gf_log(worker->conf->this->name, GF_LOG_ERROR, "jy_message:worker %d over limit!", worker->thread_idx);
						//iot_qos_notify_wait(worker, stub->limit_time);
					}
				}
				
        }

out:
	UNLOCK (&worker->qlock);
	
        iot_destroy_request (worker, req);

	return stub;
}

//QoS
//use stub instead req
call_stub_t *
iot_dequeue_ordered_with_stub (iot_worker_t *worker)
{
	call_stub_t     *stub = NULL;
	//iot_request_t   *req = NULL;
    int              waitstat = 0;
	
	iot_conf_t *conf = worker->conf;
	struct timeval now;

	pthread_mutex_lock(&conf->otlock);
	//LOCK (&worker->qlock);
        {
loop:
                //while (!worker->queue_size) {
				while (list_empty(&conf->normal_req) && list_empty(&conf->priority_req ))
				{
                        waitstat = 0;
                        waitstat = iot_qos_ordered_request_wait (worker);
                        /* We must've timed out and are now required to
                         * exit.
                         */
                        if (waitstat == -1)
                                goto out;
				}
				
				//deque
				{
					if(!list_empty(&conf->priority_req)){
					//priority queue
										
						//gf_log(conf->this->name, GF_LOG_ERROR, "jy_message: worker %d deal priority queue", worker->thread_idx);
						//stub = iot_qos_priority_dequeue_ordered (conf);
						list_for_each_entry (stub, &conf->priority_req, list)
       						break;

					}
					else if(!list_empty(&conf->normal_req)){
					//normal queue
						list_for_each_entry (stub, &conf->normal_req, list)
       						break;

					}
					else{
						goto loop;
					}
				}

                list_del_init(&stub->list);
				

				//QoS
				if(stub->app != NULL && (stub->fop == GF_FOP_WRITE || stub->fop == GF_FOP_READ)){
					//gf_log(conf->this->name, GF_LOG_ERROR, "jy_message: worker %d deque. left queue_size:%d", worker->thread_idx, worker->queue_size);

					APP_Qos_Info* app = (APP_Qos_Info*) stub->app;
					pthread_mutex_lock(&app->mutex);
    				{
						app->queue_size--;
					}
					pthread_mutex_unlock(&app->mutex);

				}
				
				//check app eviction and print app throughput
				gettimeofday(&now,NULL);
				if(now.tv_sec > conf->ctime.tv_sec){
					conf->ctime = now;
					iot_qos_eviction_and_print_app_throughput(conf);
				}

				
		}
	

out:
	//UNLOCK (&worker->qlock);
	pthread_mutex_unlock(&conf->otlock);

        //iot_destroy_request (worker, req);

	return stub;
}

void *
iot_worker_ordered (void *arg)
{
        iot_worker_t    *worker = arg;
        call_stub_t     *stub = NULL;

		//QoS
		//iot_conf_t      *conf = worker->conf;
		

	while (1) {
		
		if(stub == NULL){
			stub = iot_dequeue_ordered_with_stub(worker);
		}

                //.stub = iot_dequeue_ordered (worker);
                

		
                /* If stub is NULL, we must've timed out waiting for a
                 * request and have now been allowed to exit.
                 */
                if (!stub)
                        break;

		call_resume (stub);

		stub = NULL;
	}

        return NULL;
}

void*
iot_qos_lworker(void *arg){
	limit_worker *worker = arg;
	call_stub_t *stub = NULL;
	iot_conf_t *conf = worker->conf;
	int waitstat = 0;
		
	while (1) {
		pthread_mutex_lock(&worker->qlock);
		while (list_empty(&worker->rqlist))
		{
			waitstat = 0;
			waitstat = iot_qos_lworker_wait (worker);
			if (waitstat == -1)
				goto out;
		}

		list_for_each_entry (stub, &worker->rqlist, list)
			break;
		
		//pthread_mutex_unlock(&worker->qlock);
		list_del_init(&stub->list);

		if(stub->app != NULL && (stub->fop == GF_FOP_WRITE || stub->fop == GF_FOP_READ)){
			while(iot_qos_is_over_limit_time(stub->limit_time) == _gf_false){
				//gf_log(worker->conf->this->name, GF_LOG_ERROR, "jy_message:worker %d over limit!", worker->thread_idx);
				iot_qos_notify_limit_wait(worker, stub->limit_time);
				/*while(1){
					struct timeval cur_time;
					gettimeofday(&cur_time,NULL);
					double difftime = (cur_time.tv_sec-stub->limit_time.tv_sec)*1000000+cur_time.tv_usec-stub->limit_time.tv_usec;
					if(difftime>=0){
						break;
					}
				}*/
			}
		}
		pthread_mutex_unlock(&worker->qlock);

		if (!stub)
			break;
		pthread_mutex_lock(&conf->otlock);
		list_add_tail(&stub->list, &conf->normal_req);
		pthread_cond_broadcast (&conf->ot_notifier);
		pthread_mutex_unlock(&conf->otlock);
		//call_resume (stub);

		stub = NULL;
	}
out:
        return NULL;
}



/* Must be called with worker lock held. */
gf_boolean_t
iot_can_unordered_exit (iot_worker_t * worker)
{
        gf_boolean_t    allow_exit = _gf_false;
        iot_conf_t      *conf = NULL;

        conf = worker->conf;
        /* We dont want this thread to exit if its index is
         * below the min thread count.
         */
        if (worker->thread_idx >= conf->min_u_threads)
                allow_exit = _gf_true;

        return allow_exit;
}


/* Must be called with worker lock held. */
gf_boolean_t
iot_unordered_exit (int cond_waitres, iot_worker_t *worker)
{
        gf_boolean_t     allow_exit = _gf_false;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                allow_exit = _gf_true;
        } else if (cond_waitres == ETIMEDOUT) {
                allow_exit = iot_can_unordered_exit (worker);
        }

        if (allow_exit) {
                worker->state = IOT_STATE_DEAD;
                worker->thread = 0;
        }

        return allow_exit;
}


int
iot_unordered_request_wait (iot_worker_t * worker)
{
        int             waitres = 0;
        int             retstat = 0;

        if (worker->state == IOT_STATE_EXIT_REQUEST) {
                retstat = -1;
                goto out;
        }

        waitres = iot_notify_wait (worker, worker->conf->u_idle_time);
        if (iot_unordered_exit (waitres, worker)) {
                retstat = -1;
        }

out:
        return retstat;
}


call_stub_t *
iot_dequeue_unordered (iot_worker_t *worker)
{
        call_stub_t     *stub= NULL;
        iot_request_t   *req = NULL;
        int              waitstat = 0;

	LOCK (&worker->qlock);
        {
                while (!worker->queue_size) {
                        waitstat = 0;
                        waitstat = iot_unordered_request_wait (worker);
                        /* If -1, request wait must've timed
                         * out.
                         */
                        if (waitstat == -1)
                                goto out;
                }

                list_for_each_entry (req, &worker->rqlist, list)
                        break;
                list_del (&req->list);
                stub = req->stub;

                worker->queue_size--;
        }
out:
	UNLOCK (&worker->qlock);
        iot_destroy_request (worker, req);

	return stub;
}


void *
iot_worker_unordered (void *arg)
{
        iot_worker_t    *worker = arg;
        call_stub_t     *stub = NULL;

	while (1) {

		stub = iot_dequeue_unordered (worker);
                /* If no request was received, we must've timed out,
                 * and can exit. */
                if (!stub)
                        break;

		call_resume (stub);
	}

        return NULL;
}


void
deallocate_worker_array (iot_worker_t **workers)
{
        FREE (workers);
}

void
deallocate_workers (iot_worker_t **workers,
                    int start_alloc_idx, int count)
{
        int     i;
        int     end_count;

        end_count = count + start_alloc_idx;
        for (i = start_alloc_idx; (i < end_count); i++) {
                if (workers[i] != NULL) {
                        mem_pool_destroy (workers[i]->req_pool);
                        FREE (workers[i]);
                        workers[i] = NULL;
                }
        }
        
}


iot_worker_t **
allocate_worker_array (int count)
{
        iot_worker_t    **warr = NULL;

        warr = CALLOC (count, sizeof (iot_worker_t *));

        return warr;
}


iot_worker_t *
allocate_worker (iot_conf_t * conf)
{
        iot_worker_t    *wrk = NULL;

        wrk = CALLOC (1, sizeof (iot_worker_t));
        if (wrk == NULL) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                goto out;
        }

        wrk->req_pool = mem_pool_new (iot_request_t, IOT_REQUEST_MEMPOOL_SIZE);
        if (wrk->req_pool == NULL)
                goto free_wrk;

        INIT_LIST_HEAD (&wrk->rqlist);
        wrk->conf = conf;
        iot_notify_init (wrk);
        wrk->state = IOT_STATE_DEAD;

out:
        return wrk;

free_wrk:
        FREE (wrk);
        return NULL;
}


int
allocate_workers (iot_conf_t *conf, iot_worker_t **workers, int start_alloc_idx,
                  int count)
{
        int     i;
        int     end_count, ret = -1;

        end_count = count + start_alloc_idx;
        for (i = start_alloc_idx; i < end_count; i++) {
                workers[i] = allocate_worker (conf);
                if (workers[i] == NULL) {
                        ret = -ENOMEM;
                        goto out;
                }
                workers[i]->thread_idx = i;

			//QoS message
			gf_log(conf->this->name, GF_LOG_ERROR, "jy_message:allocate worker %d!",i);
        }

        ret = 0;

out:
        return ret;
}


void
iot_stop_worker (iot_worker_t *worker)
{
        LOCK (&worker->qlock);
        {
                worker->state = IOT_STATE_EXIT_REQUEST;
        }
        UNLOCK (&worker->qlock);

        iot_notify_worker (worker);
        pthread_join (worker->thread, NULL);
}


void
iot_stop_workers (iot_worker_t **workers, int start_idx, int count)
{
        int     i = 0;
        int     end_idx = 0;

        end_idx = start_idx + count;
        for (i = start_idx; i < end_idx; i++) {
                if (workers[i] != NULL) {
                        iot_stop_worker (workers[i]);
                }
        }
}


int
iot_startup_worker (iot_worker_t *worker, iot_worker_fn workerfunc)
{
        int     ret = -1;
        ret = pthread_create (&worker->thread, &worker->conf->w_attr,
                              workerfunc, worker);
        if (ret != 0) {
                gf_log (worker->conf->this->name, GF_LOG_ERROR,
                        "cannot start worker (%s)", strerror (errno));
                ret = -ret;
        } else {
                worker->state = IOT_STATE_ACTIVE;
        }

        return ret;
}


int
iot_startup_workers (iot_worker_t **workers, int start_idx, int count,
                     iot_worker_fn workerfunc)
{
        int     i = 0;
        int     end_idx = 0;
        int     ret = -1; 

        end_idx = start_idx + count;
        for (i = start_idx; i < end_idx; i++) {
                ret = iot_startup_worker (workers[i], workerfunc);
                if (ret < 0) {
                        goto out;
                }
        //Qos
        gf_log(workers[i]->conf->this->name, GF_LOG_ERROR, "jy_message:startup worker %d!", i);
        }

        ret = 0;
out:
        return ret;
}


void
set_stack_size (iot_conf_t *conf)
{
        int     err = 0;
        size_t  stacksize = IOT_THREAD_STACK_SIZE;

        pthread_attr_init (&conf->w_attr);
        err = pthread_attr_setstacksize (&conf->w_attr, stacksize);
        if (err == EINVAL) {
                gf_log (conf->this->name, GF_LOG_WARNING,
                                "Using default thread stack size");
        }
}

void
iot_cleanup_workers (iot_conf_t *conf)
{
		//QoS clean limit _worker
		pthread_mutex_lock (&conf->lworker->qlock);
        {
                conf->lworker->state = IOT_STATE_EXIT_REQUEST;
        }
        pthread_mutex_unlock (&conf->lworker->qlock);
        pthread_cond_broadcast (&conf->lworker->notifier);
        pthread_join (conf->lworker->thread, NULL);

		CRedisSubscriber *p = (CRedisSubscriber *)conf->sub;
		if(p != NULL)
			p->state = IOT_STATE_EXIT_REQUEST;
		sub_exit(conf);
		
		
        if (conf->uworkers != NULL) {
                iot_stop_workers (conf->uworkers, 0,
                                  conf->max_u_threads);
                    
                deallocate_workers (conf->uworkers, 0,
                                    conf->max_u_threads);

                deallocate_worker_array (conf->uworkers);
        }
                
        if (conf->oworkers != NULL) {
                iot_stop_workers (conf->oworkers, 0,
                                  conf->max_o_threads);
                        
                deallocate_workers (conf->oworkers, 0,
                                    conf->max_o_threads);
                        
                deallocate_worker_array (conf->oworkers);
        }
}

limit_worker*
iot_qos_init_limit_worker (iot_conf_t * conf)
{
        limit_worker* wrk = NULL;

        wrk = CALLOC (1, sizeof (limit_worker));
        if (wrk == NULL) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                goto out;
        }

        INIT_LIST_HEAD (&wrk->rqlist);
        wrk->conf = conf;

		pthread_mutex_init (&wrk->qlock, NULL);
		pthread_cond_init (&wrk->notifier, NULL);
        wrk->state = IOT_STATE_DEAD;

		int ret = pthread_create (&wrk->thread, &conf->w_attr,
                              iot_qos_lworker, wrk);
        if (ret != 0) {
                gf_log (wrk->conf->this->name, GF_LOG_ERROR,
                        "cannot start worker (%s)", strerror (errno));
				goto free_wrk;
        } else {
                wrk->state = IOT_STATE_ACTIVE;
        }

out:
        return wrk;

free_wrk:
        FREE (wrk);
        return NULL;
}


int
workers_init (iot_conf_t *conf)
{
        int     ret = -1;

        if (conf == NULL) {
                ret = -EINVAL;
                goto err;
        }

		//QoS: init limit worker
		conf->lworker = iot_qos_init_limit_worker(conf);

        /* Initialize un-ordered workers */
       /* conf->uworkers = allocate_worker_array (conf->max_u_threads);
        if (conf->uworkers == NULL) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                ret = -ENOMEM;
                goto err;
        }

        ret = allocate_workers (conf, conf->uworkers, 0,
                                conf->max_u_threads);
        if (ret < 0) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                goto err;
        }*/

        /* Initialize ordered workers */
        conf->oworkers = allocate_worker_array (conf->max_o_threads);
        if (conf->oworkers == NULL) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                ret = -ENOMEM;
                goto err;
        }

        ret = allocate_workers (conf, conf->oworkers, 0,
                                conf->max_o_threads);
        if (ret < 0) {
                gf_log (conf->this->name, GF_LOG_ERROR, "out of memory");
                goto err;
        }

        set_stack_size (conf);
        ret = iot_startup_workers (conf->oworkers, 0, conf->min_o_threads,
                                   iot_worker_ordered);
        if (ret == -1) {
                /* logged inside iot_startup_workers */
                goto err;
        }

        /*ret = iot_startup_workers (conf->uworkers, 0, conf->min_u_threads,
                                   iot_worker_unordered);
        if (ret == -1) {
                // logged inside iot_startup_workers 
                goto err;
        }*/
    //Qos
    gf_log(conf->this->name, GF_LOG_ERROR, "jy_message:init %d workers over!", conf->thread_count);

        return 0;

err:
        if (conf != NULL)  {
                iot_cleanup_workers (conf);
        }

        return ret;
}


int
init (xlator_t *this)
{
        iot_conf_t      *conf = NULL;
        dict_t          *options = this->options;
        int             thread_count = IOT_DEFAULT_THREADS;
        gf_boolean_t    autoscaling = IOT_SCALING_OFF;
        char            *scalestr = NULL;
        int             min_threads, max_threads, ret = -1;
        
	if (!this->children || this->children->next) {
		gf_log ("io-threads", GF_LOG_ERROR,
			"FATAL: iot not configured with exactly one child");
                goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	conf = (void *) CALLOC (1, sizeof (*conf));
        if (conf == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "out of memory");
                goto out;
        }

        if ((dict_get_str (options, "autoscaling", &scalestr)) == 0) {
                if ((gf_string2boolean (scalestr, &autoscaling)) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                        "'autoscaling' option must be"
                                        " boolean");
                        goto out;
                }
        }

	if (dict_get (options, "thread-count")) {
                thread_count = data_to_int32 (dict_get (options,
                                        "thread-count"));
                if (scalestr != NULL)
                        gf_log (this->name, GF_LOG_WARNING,
                                        "'thread-count' is specified with "
                                        "'autoscaling' on. Ignoring"
                                        "'thread-count' option.");
                if (thread_count < 2)
                        thread_count = IOT_MIN_THREADS;
        }

        min_threads = IOT_DEFAULT_THREADS;
        max_threads = IOT_MAX_THREADS;
        if (dict_get (options, "min-threads"))
                min_threads = data_to_int32 (dict_get (options,
                                        "min-threads"));

        if (dict_get (options, "max-threads"))
                max_threads = data_to_int32 (dict_get (options,
                                        "max-threads"));
       
        if (min_threads > max_threads) {
                gf_log (this->name, GF_LOG_ERROR, " min-threads must be less "
                                "than max-threads");
                goto out;
        }

        /* If autoscaling is off, then adjust the min and max
         * threads according to thread-count.
         * This is based on the assumption that despite autoscaling
         * being off, we still want to have separate pools for data
         * and meta-data threads.
         */
        if (!autoscaling)
                max_threads = min_threads = thread_count;

        /* If user specifies an odd number of threads, increase it by
         * one. The reason for having an even number of threads is
         * explained later.
         */
        if (max_threads % 2)
                max_threads++;

        if(min_threads % 2)
                min_threads++;

        /* If the user wants to have only a single thread for
        * some strange reason, make sure we set this count to
        * 2. Explained later.
        */
        if (min_threads < IOT_MIN_THREADS)
                min_threads = IOT_MIN_THREADS;

        /* Again, have atleast two. Read on. */
        if (max_threads < IOT_MIN_THREADS)
                max_threads = IOT_MIN_THREADS;

        /* This is why we need atleast two threads.
         * We're dividing the specified thread pool into
         * 2 halves, equally between ordered and unordered
         * pools.
         */

        /* Init params for un-ordered workers. */
        pthread_mutex_init (&conf->utlock, NULL);
        conf->max_u_threads = max_threads / 2;
        conf->min_u_threads = min_threads / 2;
        conf->u_idle_time = IOT_DEFAULT_IDLE;
        conf->u_scaling = autoscaling;

        /* Init params for ordered workers. */
        pthread_mutex_init (&conf->otlock, NULL);
        conf->max_o_threads = max_threads ;
        conf->min_o_threads = min_threads ;
        conf->o_idle_time = IOT_DEFAULT_IDLE;
        conf->o_scaling = autoscaling;

        gf_log (this->name, GF_LOG_DEBUG,
                "io-threads: Autoscaling: %s, "
                "min_threads: %d, max_threads: %d",
                (autoscaling) ? "on":"off", min_threads, max_threads);

        conf->this = this;

    //Qos
    INIT_LIST_HEAD(&conf->apps);
	INIT_LIST_HEAD(&conf->priority_req);
	INIT_LIST_HEAD(&conf->normal_req);
	pthread_cond_init (&conf->ot_notifier, NULL);
	pthread_cond_init (&conf->limit_notifier, NULL);
    conf->app_count = 0;
	conf->rand = 0;
	gettimeofday(&conf->ctime,NULL);
	//get QoS setting
	if (dict_get (options, "default-reserve"))
                conf->default_reserve = data_to_int32 (dict_get (options,
                                        "default-reserve"));
	else
		conf->default_reserve = DEFAULT_RESERVE;
	if (dict_get (options, "default-limit"))
                conf->default_limit = data_to_int32 (dict_get (options,
                                        "default-limit"));
	else
		conf->default_limit = DEFAULT_LIMIT;
	if (dict_get (options, "default-BW")){
                conf->default_BW = data_to_int32 (dict_get (options,
                                        "default-BW"));
				conf->default_BW *= 1024;	//converted to KB / s
		}
	else
		conf->default_BW = IOT_MAX_BANDWIDTH_BIG;
	conf->BW_BIG = conf->default_BW;
	conf->BW_SMALL = conf->default_BW/2;

	char *redis_host = NULL;
	int redis_port = 0;
	if (dict_get (options, "redis-host"))
		redis_host = data_to_str (dict_get (options, "redis-host"));
	if (dict_get (options, "redis-port"))
		redis_port = data_to_int32 (dict_get (options, "redis-port"));

	if(redis_host){
		conf->redis_host = CALLOC (1, strlen(redis_host));
		ERR_ABORT(conf->redis_host);
		strcpy(conf->redis_host, redis_host);
	}
	else
		conf->redis_host = NULL;
	conf->redis_port = redis_port;

	gf_log (this->name, GF_LOG_ERROR, "jy-setting:	reserve:%d	limit:%d,	BW:%d", conf->default_reserve, conf->default_limit, conf->default_BW);

		
	ret = workers_init (conf);
        if (ret == -1) {
                gf_log (this->name, GF_LOG_ERROR,
                        "cannot initialize worker threads, exiting init");
                FREE (conf);
                goto out;
        }
	
	conf->sub = NULL;
 	//int sub_ret = pthread_create (&conf->sub_thread, &conf->w_attr, sub_worker, conf);
    if (sub_worker(conf) == NULL) {
            gf_log (conf->this->name, GF_LOG_ERROR,
                    "cannot start worker (%s)", strerror (errno));
    }

	this->private = conf;
        ret = 0;
out:
	return ret;
}


void
fini (xlator_t *this)
{
	iot_conf_t *conf = this->private;

	//QoS free
	APP_Qos_Info *tmp_app;
	while(conf->app_count > 0){
		conf->app_count -= 1;
		list_for_each_entry (tmp_app, &conf->apps, apps)
			break;
		list_del(&tmp_app->apps);
		free(tmp_app);
	}
	list_del(&conf->apps);
	list_del(&conf->priority_req);
	list_del(&conf->normal_req);

	FREE (conf);

	this->private = NULL;
	return;
}

/*
 * O - Goes to ordered threadpool.
 * U - Goes to un-ordered threadpool.
 * V - Variable, depends on whether the file is open.
 *     If it is, then goes to ordered, otherwise to
 *     un-ordered.
 */
struct xlator_fops fops = {      
	.readv       = iot_readv,       /* O */
	.writev      = iot_writev,      /* O */
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {"thread-count"}, 
	  .type = GF_OPTION_TYPE_INT, 
	  .min  = IOT_MIN_THREADS, 
	  .max  = IOT_MAX_THREADS
	},
        { .key  = {"autoscaling"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key          = {"min-threads"},
          .type         = GF_OPTION_TYPE_INT,
          .min          = IOT_MIN_THREADS,
          .max          = IOT_MAX_THREADS,
          .description  = "Minimum number of threads must be greater than or "
                          "equal to 2. If the specified value is less than 2 "
                          "it is adjusted upwards to 2. This is a requirement"
                          " for the current model of threading in io-threads."
        },
        { .key          = {"max-threads"},
          .type         = GF_OPTION_TYPE_INT,
          .min          = IOT_MIN_THREADS,
          .max          = IOT_MAX_THREADS,
          .description  = "Maximum number of threads is advisory only so the "
                          "user specified value will be used."
        },
        { .key  = {"default-reserve"},
          .type = GF_OPTION_TYPE_INT,
        },
        { .key  = {"default-limit"},
          .type = GF_OPTION_TYPE_INT,
        },
        { .key  = {"default-BW"},
          .type = GF_OPTION_TYPE_INT,
        },
        { .key  = {"redis-host"},
          .type = GF_OPTION_TYPE_STR,
        },
        { .key  = {"redis-port"},
          .type = GF_OPTION_TYPE_INT,
        },
	{ .key  = {NULL} },
};
