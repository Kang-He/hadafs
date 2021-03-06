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

/**
 * xlators/debug/qos_monitor :
 *    This translator monitor following metrics and publish to redis chanenl per interval:
 *    a) app_rbw: throughput of read operation - interval - per clien_id 
 *    b) app_wbw: throughput of writev operation - interval - per clien_id 
 *    c) app_r_delay: times of read operation - interval - per clien_id 
 *    d) app_w_delay: times of writev operation - interval - per clien_id 
 *    e) app_diops: times of io operation - interval - per clien_id
 */

#include "qos_monitor.h"
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

/* return the difference of begin and end by second*/
double time_difference(struct timeval *begin, struct timeval *end)
{
	double duration = 0;
	if (begin == NULL || end == NULL)
		return duration;
	duration = (end->tv_sec - begin->tv_sec) + ((end->tv_usec - begin->tv_usec) / 1000000);
	return duration;
}

double time_difference_ms(struct timeval *begin, struct timeval *end)
{
	double duration = 0;
	if (begin == NULL || end == NULL)
		return duration;
	duration = (end->tv_sec - begin->tv_sec) * 1000 + ((end->tv_usec - begin->tv_usec) / 1000);
	return duration;
}

double time_difference_us(struct timeval *begin, struct timeval *end)
{
	double duration = 0;
	if (begin == NULL || end == NULL)
		return duration;
	duration = (end->tv_sec - begin->tv_sec) * 1000000 + ((end->tv_usec - begin->tv_usec));
	return duration;
}



/* return the index of n-th pos that f appears in str*/
int find_str_n(char *str, char *f, int n)
{
    int i;
    char *tmp;
    int len = strlen(str);

    // check
    if (str == NULL || f == NULL || n > len || n < 0)
    {
        return -1;
    }

    tmp = strstr(str, f);
    for (i = 1; i < n && tmp != NULL; ++i)
    {
        tmp = strstr(tmp + strlen(f), f);
    }

    if (i != n)
        return -1;
    else
        return len - strlen(tmp);
}

/* according to current client_id_t info to get client_id 
 * TODO: maybe should modify with the map relation with client and application
*/
void get_client_id(char *client, char *client_id)
{
	if (client == NULL) {
		gf_log("monitor", GF_LOG_ERROR,
               "client is NULL!\n");
	} else {
		int len = find_str_n(client, DELIMER, TIMES);
		// ?????????
		if (len == -1) {
			strncpy(client_id, client, strlen(client));
		} else {
			strncpy(client_id, client, len);
			client_id[len] = '\0';
		} 
	}
}

/* hiredis ????????????*/
// ????????????????????????
void *event_proc(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    sem_wait(&p->_event_sem);

	// ?????????????????????event_base_dispatch?????????
    event_base_dispatch(p->_event_base);

    return NULL;
}

void *event_thread(void *data)
{
    if (NULL == data)
    {
        gf_log("monitor", GF_LOG_ERROR,
               "even_thread Error!\n");
        return NULL;
    }

    return event_proc(data);
}

int get_next_tag(int idx, const char* const msg){                                                                                                                                            
	if(idx < 0) return -1;
	while(msg[idx] != '\0' && msg[idx] != '^'){
		idx++;
	}
	if(msg[idx] == '\0' ||msg[idx + 1] != '^' ){
		return -1;
	}
	idx += 2;
	return idx;
}

int get_nodename(const char* const msg, char* hostname) {
    if (strlen(msg) == 0)
        return 0;
    int idx = 0;
    idx = get_next_tag(idx, msg);

    if (idx < 0) {
        strcpy(hostname, msg);
        return 1;
    }


    idx -= 2;


    int i = 0;
    for (i = 0; i < 60 && i < idx; i++) {
        hostname[i] = msg[i];
    }
    if (i == 60) return 0;
    hostname[i] = '\0';
    return 1;
}


void dealreply(qos_monitor_private_t *p, redisReply *redis_reply){
	if (redis_reply->type == REDIS_REPLY_ARRAY && redis_reply->elements == 3){
		if(strncmp(redis_reply->element[1]->str,  "monitor", strlen( "monitor")) != 0)

			return;
		int i = 0;
		int idx = 0;
		int ret = 0;
		for(i = 0; i < redis_reply->elements; i++){
			gf_log("monitor", GF_LOG_ERROR, "monitor: sub: NO.%d  message: %s", i, redis_reply->element[i]->str);
		}

		if(strncmp(redis_reply->element[0]->str,  "message", strlen( "message")) != 0){
			return;
		}
		   
		gf_log("monitor", GF_LOG_ERROR, "monitor: sub:deal message");
		

		if (redis_reply->element[2]->str == NULL) return;
        if (strncmp(redis_reply->element[2]->str, "app_nodes", strlen("app_nodes")) == 0) {
			char *appname = CALLOC(60,sizeof(char));
			char* msg;
			idx = get_next_tag(idx, redis_reply->element[2]->str);
			msg = redis_reply->element[2]->str + idx;
			get_nodename(msg, appname);
            while (1) {
                idx = get_next_tag(idx, redis_reply->element[2]->str);
                if (idx == -1) 
                    break;
                char hostname[60];
                msg = redis_reply->element[2]->str + idx;
                if (get_nodename(msg, hostname)) {
                    gf_log("monitor", GF_LOG_ERROR, "monitor: node:%s will be inserted into app:%s", hostname, appname);
                    LOCK(&p->lock);
                    //dict_ref(p->node_appname);
					//dict_set_str(p->node_appname, hostname, appname );
					if(dict_set_str(p->node_appname, hostname, (char *)appname ) != 0)
						gf_log("monitor", GF_LOG_ERROR, "set failed");
					else{
						char *testchar = NULL;
						dict_get_ptr(p->node_appname, hostname, &testchar );
						gf_log("monitor", GF_LOG_ERROR, "set success, %s->%s", hostname, testchar);
						dict_get_str(p->node_appname, hostname, &testchar );
                        gf_log("monitor", GF_LOG_ERROR, "set str, %s->%s", hostname, testchar);
					}
					//dict_unref(p->node_appname);
                    UNLOCK(&p->lock);
                }   
            }   
            return;
                                                                                                                                                                                             
        }else if(strncmp(redis_reply->element[2]->str, "remove_app", strlen("remove_app")) == 0){
			char* msg;
            while (1) {
                idx = get_next_tag(idx, redis_reply->element[2]->str);
                if (idx == -1) 
                    break;
                char hostname[60];
                msg = redis_reply->element[2]->str + idx;
                if (get_nodename(msg, hostname)) {
                    gf_log("monitor", GF_LOG_ERROR, "monitor: node:%s will be deleted", hostname);
                    LOCK(&p->lock);
                    //dict_ref(p->node_appname);			
					char *testchar = NULL;
					if(dict_get_ptr(p->node_appname, hostname, &testchar )!= 0)
						gf_log("monitor", GF_LOG_ERROR, "no %s exites", hostname);
                    else
						gf_log("monitor", GF_LOG_ERROR, "delete, %s->%s", hostname, testchar);
					dict_del(p->node_appname, hostname);
					//dict_unref(p->node_appname);
                    UNLOCK(&p->lock);
                }   
            }   
            return;
            		
		}
	}
  	
}
void subCallback(redisAsyncContext *c, void *r, void *priv) 
{
    redisReply *reply = (redisReply *)r;
	/*struct timeval now;*/
    if (reply == NULL) return;
	/*gettimeofday(&now, NULL);*/
	/*gf_log("monitor", GF_LOG_INFO,
               "[pub_cbk] %ld\n", now.tv_sec*1000000+now.tv_usec);*/

	//jy-test
	qos_monitor_private_t *private = (qos_monitor_private_t *)priv; 
	//CRedisPublisher *p;
	//priv_t = (CRedisPublisher *)priv;
	gf_log("monitor", GF_LOG_INFO,
               "[sub_cbk]. reply_type %d\n", reply->type);
	dealreply(private, reply);	
} 


void pubCallback(redisAsyncContext *c, void *r, void *priv) 
{
    redisReply *reply = (redisReply *)r;
	/*struct timeval now;*/
    if (reply == NULL) return;
	/*gettimeofday(&now, NULL);*/
	/*gf_log("monitor", GF_LOG_INFO,
               "[pub_cbk] %ld\n", now.tv_sec*1000000+now.tv_usec);*/

	//jy-test
	CRedisPublisher *priv_t;
	priv_t = (CRedisPublisher *)priv;
	pthread_mutex_lock(&priv_t->qlock);
	{
		pthread_cond_broadcast(&priv_t->notifier);
	}
	pthread_mutex_unlock(&priv_t->qlock);
} 

 
void connectCallback(const redisAsyncContext *c, int status) 
{
    if (status != REDIS_OK) {
		gf_log("monitor", GF_LOG_ERROR,
               "Error: %s\n", c->errstr);
        return;
    }
	gf_log("monitor", GF_LOG_INFO,
               "Connected...\n");
}
 
void disconnectCallback(const redisAsyncContext *c, int status) 
{
    if (status != REDIS_OK) {
		gf_log("monitor", GF_LOG_ERROR,
               "Error: %s\n", c->errstr);
        return;
    }
    gf_log("monitor", GF_LOG_INFO,
               "Disconnected...\n");

	DISCONNECT_FLAG = 0;
}


/* CRedisPublisher */
int redis_init(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    // initialize the event
    p->_event_base = event_base_new();    
    if (NULL == p->_event_base)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Create redis event failed.\n");
        return 0;
    }

    memset(&p->_event_sem, 0, sizeof(p->_event_sem));
    int ret = sem_init(&p->_event_sem, 0, 0);
    if (ret != 0)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Init sem failed.\n");
        return 0;
    }

    return 1;
}

int redis_uninit(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
	event_base_free(p->_event_base);
    p->_event_base = NULL;

    sem_destroy(&p->_event_sem);
	
	if (p->redis_host != NULL) {
		FREE(p->redis_host);
		p->redis_host = NULL;
	}
	if (p->channel != NULL) {
		FREE(p->channel);
		p->channel = NULL;
	}
		
    return 1;
}

int redis_disconnect(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    if (p->_redis_context)
    {
        redisAsyncDisconnect(p->_redis_context);
        p->_redis_context = NULL;
    }

    return 1;
}

void *syncsubscribe( void *priv)                                                                                                                                                             
{
	gf_log("monitor", GF_LOG_ERROR, " sub begin...");
    //redisContext *rc = redisConnect("40.0.20.111", 9809);
	qos_monitor_private_t *private = (qos_monitor_private_t *)priv;
    redisReply *reply = redisCommand(private->publisher->sync_redis_context, "SUBSCRIBE %s", "monitor");
	//redisReply *reply = redisCommand(rc, "SUBSCRIBE %s", "monitor");
	//gf_log("monitor", GF_LOG_ERROR, " sub: reply message. reply_type:%d", reply->type);
    freeReplyObject(reply);
    while(redisGetReply(private->publisher->sync_redis_context, (void **)&reply) == REDIS_OK){
		if(reply == NULL){
			gf_log("monitor", GF_LOG_ERROR, " sub: reply = NULL");
            return;
		}
        else{
            gf_log("monitor", GF_LOG_ERROR, " sub: get command_callback message. reply_type:%d", reply->type);
            dealreply(private, reply);
        }
		freeReplyObject(reply);
    }   
}


int redis_syncconnect(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    // connect redis
    p->sync_redis_context = redisConnect(p->redis_host, p->redis_port);    // ???????????????redis?????????????????????????????????
    if (NULL == p->sync_redis_context)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Connect redis failed.\n");
        return 1;
    }

    if (p->sync_redis_context->err)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Connect redis error: %d, %s\n",
            p->sync_redis_context->err, p->sync_redis_context->errstr);    // ??????????????????
        return 1;
    }
	gf_log("monitor", GF_LOG_ERROR,
               "Connect redis ok\n");	
	return 0;
}


int redis_connect(void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    // connect redis
    p->_redis_context = redisAsyncConnect(p->redis_host, p->redis_port);    // ???????????????redis?????????????????????????????????
    if (NULL == p->_redis_context)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Connect redis failed.\n");
        return 0;
    }

    if (p->_redis_context->err)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "Connect redis error: %d, %s\n",
            p->_redis_context->err, p->_redis_context->errstr);    // ??????????????????
        return 0;
    }

    // attach the event
    redisLibeventAttach(p->_redis_context, p->_event_base);    // ??????????????????redis context??????????????????redis????????????????????????

    // ????????????????????????
    int ret = pthread_create(&p->_event_thread, NULL, event_thread, (void *)p);
    if (ret != 0)
    {
		gf_log("monitor", GF_LOG_ERROR,
               "create event thread failed.\n");
        redis_disconnect(p);
        return 0;
    }

	// ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    int tempret = redisAsyncSetConnectCallback(p->_redis_context, &connectCallback);
    gf_log("monitor", GF_LOG_ERROR, "hk_message: tempret = %d", tempret);
	// ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    redisAsyncSetDisconnectCallback(p->_redis_context, &disconnectCallback);

	// ??????????????????
    sem_post(&p->_event_sem);
    return 1;
}
int subscribe(const char *channel_name,  qos_monitor_private_t *priv)
{
    CRedisPublisher *p = priv->publisher;
    int ret = redisAsyncCommand(p->_redis_context,
        &subCallback, priv, "SUBSCRIBE %s",
        channel_name);
    if (REDIS_ERR == ret)
    {
        gf_log("monitor", GF_LOG_ERROR,
               "Subscribe command failed: %d\n", ret);
        return 0;
    } else {
        gf_log("monitor", GF_LOG_INFO,
                "Subscribe %s\n", channel_name);
        return 1;
    }
}

int publish(const char *channel_name, const char *message, void *pthis)
{
    CRedisPublisher *p = (CRedisPublisher *)pthis;
    int ret = redisAsyncCommand(p->_redis_context,
        &pubCallback, p, "PUBLISH %s %s",
        channel_name, message);
    if (REDIS_ERR == ret)
    {
        gf_log("monitor", GF_LOG_ERROR,
               "Publish command failed: %d\n", ret);
        return 0;
    } else {
		/*gf_log("monitor", GF_LOG_INFO,
               "publish %s %s\n", channel_name, message);*/
        return 1;
    }
}

static void
qos_monitor_data_clear(dict_t *metrics)
{
	ERR_ABORT (metrics);  
	//gf_log("monitor", GF_LOG_INFO, "enter qos_monitor_data_clear");
	if (metrics->count > 0)
	{
		dict_destroy(metrics);
		metrics = dict_new();
	}
	//gf_log("monitor", GF_LOG_INFO, "qos_monitor_data_clear finished.");
}

void get_server_ip(char *result)
{
	struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmpAddrPtr = NULL;
	
    getifaddrs(&ifAddrStruct);
 
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
	{
        if (!ifa->ifa_addr)
		{
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) // check it is IP4
		{
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			if (strcmp(addressBuffer, "127.0.0.1") && !strstr(addressBuffer, "10.") 
				  &&  !strstr(addressBuffer, "172.") && !strstr(addressBuffer, "192.")) {
					  strcpy(result, addressBuffer);
					  break;
				  }
				
        }
		else if (ifa->ifa_addr->sa_family == AF_INET6) // check it is IP6
		{
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
        }
    }
    if (ifAddrStruct!=NULL)
	{
		freeifaddrs(ifAddrStruct);
	}
}

int redis_wait(CRedisPublisher* publisher, int N){
	if(N <= 0 || N > 10) {
		gf_log("jy-test", GF_LOG_INFO, "redis_wait: N out of range: %d", N);
		return 0;
	}

	int waitres = 0;
	pthread_mutex_lock(&publisher->qlock);
	{
		struct timespec ts = {0, };
		struct timeval tv;
		gettimeofday (&tv, NULL);
		
        ts.tv_nsec = tv.tv_usec * 1000;
		ts.tv_sec = tv.tv_sec + PUBLISH_WAIT_SEC * N;

        waitres = pthread_cond_timedwait (&publisher->notifier, &publisher->qlock, &ts);
	}
	pthread_mutex_unlock(&publisher->qlock);
	return waitres;
}


// TODO?????????????????????????????????????????????????????????????????????????????????+??????????????????
void func(dict_t *this, char *key, data_t *value, void *data)
{
	if(strncmp(key, "vn", strlen("vn")) == 0)
		return;
	//gf_log("monitor", GF_LOG_INFO, "enter func");
	char message[MSGLEN];
	qos_monitor_private_t *priv = NULL;
	struct qos_monitor_data *monitor_data = NULL;
	struct timeval now;
	char server_ip[16];
	pid_t pid;
    long timestp = 0;	
	
	priv = (qos_monitor_private_t *)data;
	monitor_data = (struct qos_monitor_data *)data_to_ptr(value);
	
	gettimeofday(&now, NULL);
	get_server_ip(server_ip);
    pid = getpid();
	timestp = now.tv_sec * 1000 + (now.tv_usec / 1000);
	
	sprintf(message, "%s%d^^%s^^%ld^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf^^%s^^%.2lf", server_ip, pid, key, timestp
			, "app_wbw", monitor_data->data_written/priv->qos_monitor_interval
			, "app_rbw", monitor_data->data_read/priv->qos_monitor_interval
			, "app_r_delay", monitor_data->read_delay.value
			, "app_w_delay", monitor_data->write_delay.value
			, "app_data_iops", monitor_data->data_iops / priv->qos_monitor_interval
			, "app_create_iops", monitor_data->create_iops / priv->qos_monitor_interval
			, "app_open_iops", monitor_data->open_iops / priv->qos_monitor_interval
			, "app_unlink_iops", monitor_data->unlink_iops / priv->qos_monitor_interval
			, "app_stat_iops", monitor_data->stat_iops / priv->qos_monitor_interval);
	publish(priv->publisher->channel, message, priv->publisher);
	//usleep(REDIS_INTERVAL);
	//gf_log("monitor", GF_LOG_NORMAL, "after sprinf: message lenth = %d, %s", STRLEN_0(message), message);


	//jy-test
	int waitres = redis_wait(priv->publisher, 1);
	if (waitres == ETIMEDOUT) {
		gf_log("jy-test", GF_LOG_INFO, "pubCallback time out!!");
		//reconnect
		if (priv->publisher->_redis_context)
    	{
    		++priv->reconnect_times;
    		gf_log("jy-test", GF_LOG_INFO, "begin reconnect......");
			
			DISCONNECT_FLAG = 1;
			redisAsyncDisconnect(priv->publisher->_redis_context);
			
			int N = 10;
			
			while(DISCONNECT_FLAG && N > 0){
				sleep(PUBLISH_WAIT_SEC);
				gf_log("jy-test", GF_LOG_INFO, "disconnectCallback TIMEOUT!  %d th", N--);
			}
        	
        	priv->publisher->_redis_context = NULL;

			gf_log("jy-test", GF_LOG_INFO, "free event...");
			gf_log_dump_backtrace("event");
			event_base_loopexit(priv->publisher->_event_base, NULL);
			event_base_loopbreak(priv->publisher->_event_base);
			event_base_free(priv->publisher->_event_base);

			sem_destroy(&priv->publisher->_event_sem);

			int ret = redis_init(priv->publisher);
			if (!ret)
			{
				gf_log("jy-test", GF_LOG_ERROR, "Redis publisher init failed.");
			} else {
				gf_log("jy-test", GF_LOG_INFO, "Redis publisher inited.");
			}
		
			ret = redis_connect(priv->publisher);
			if (!ret)
			{
				gf_log("jy-test", GF_LOG_ERROR, "Redis reconnect failed.");
			} else {
				gf_log("jy-test", GF_LOG_INFO, "Redis reconnected.");
				++priv->reconnect_succed;
			}    
    	}
		
	}
	
    if(monitor_data->data_written == 0 && monitor_data->data_read == 0){
        dict_ref(priv->metrics);
        dict_del(priv->metrics,key);
        dict_unref(priv->metrics);
    }else{
         LOCK(&priv->metrics->lock);
         _qos_init_monitor_data(monitor_data);
         UNLOCK(&priv->metrics->lock);
    }
}

void * _qos_monitor_thread(xlator_t *this)
{
	qos_monitor_private_t *priv = NULL;
	int old_cancel_type;
	//dict_t *metrics = NULL;
	
	priv = this->private;
	/*gf_log(this->name, GF_LOG_INFO,
           "qos_monitor monitor thread started, "
           "polling IO stats every %d seconds",
           priv->qos_monitor_interval);*/

	while (1) {
		// gf_log(this->name, GF_LOG_ERROR, "qos_monitor: thread should_die: %d", priv->monitor_thread_should_die);
		if (priv->monitor_thread_should_die)
			break;

		(void)pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_cancel_type);
        //gf_log(this->name, GF_LOG_INFO, "sleep....");
		sleep(priv->qos_monitor_interval);
        (void)pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_cancel_type);
	
		
		/* publish monitor metrics */
		//gf_log(this->name, GF_LOG_INFO, "--- qos monitor publisher ---");
		if (priv->metrics) {
			dict_foreach(priv->metrics, func, priv);
		} else {
			gf_log(this->name, GF_LOG_INFO, "priv->metrics is null");
		}
		if (priv->reconnect_times != 0) {
			gf_log(this->name, GF_LOG_INFO, "priv->reconnect_times = %.1lf, succed: %.1lf", priv->reconnect_times, priv->reconnect_succed);
			priv->reconnect_times = 0;
			priv->reconnect_succed = 0;
		}
	}

	priv->monitor_thread_running = 0;
	gf_log(this->name, GF_LOG_INFO, "monitor thread terminated");
	
    return NULL;
}

int _qos_destroy_monitor_thread(qos_monitor_private_t *priv)
{
	//gf_log("sh", GF_LOG_INFO, "qos_destroy_monitor_thread invoked.");
    priv->monitor_thread_should_die = 1;
    if (priv->monitor_thread_running) {
        (void)pthread_cancel(priv->monitor_thread);
        (void)pthread_join(priv->monitor_thread, NULL);
    }
    return 0;
}

void qos_private_destroy(qos_monitor_private_t *priv)
{
	if (!priv)
		return;
	//gf_log("q", GF_LOG_INFO, "qos_private_destroy invoked.");
	if (priv->metrics)
	{
		dict_unref(priv->metrics);
		priv->metrics = NULL;
	}
	
	_qos_destroy_monitor_thread(priv);
	redis_disconnect(priv->publisher);
	redis_uninit(priv->publisher);
	
	LOCK_DESTROY (&priv->lock);
	if (priv->publisher)
	{   
		if (priv->publisher->redis_host)
		{
			FREE(priv->publisher->redis_host);
			priv->publisher->redis_host = NULL;
		}
		if (priv->publisher->channel)
		{
			FREE(priv->publisher->channel);
			priv->publisher->channel = NULL;
		}
		FREE(priv->publisher);
		priv->publisher = NULL;
	}
		
	FREE (priv);
	//gf_log("q", GF_LOG_INFO, "qos_private_destroy finished.");
}


void  _qos_init_monitor_data(struct qos_monitor_data *monitor_data)
{
	monitor_data->data_written = 0.0;
	monitor_data->data_read = 0.0;
	monitor_data->data_iops = 0.0;
	monitor_data->create_iops = 0.0;
	monitor_data->open_iops = 0.0;
	monitor_data->unlink_iops = 0.0;
	monitor_data->stat_iops = 0.0;
	gettimeofday(&monitor_data->started_at, NULL);
	// TODO: whether it's ok to set this initial.
	monitor_data->write_delay.wind_at = monitor_data->started_at;
	monitor_data->write_delay.unwind_at = monitor_data->started_at;
    monitor_data->write_delay.value = 0.0;
	monitor_data->read_delay.wind_at = monitor_data->started_at;
	monitor_data->read_delay.unwind_at = monitor_data->started_at;
	monitor_data->read_delay.value = 0.0;
	//gf_log("sh", GF_LOG_INFO, "qos_monitor_data inited.");
}





int32_t
qos_monitor_writev_cbk (call_frame_t *frame,
                     void *cookie,
                     xlator_t *this,
                     int32_t op_ret,
                     int32_t op_errno,
                     struct stat *prebuf,
                     struct stat *postbuf)
{
        qos_monitor_private_t *priv = NULL;
		client_id_t *client = NULL;
		struct qos_monitor_data *monitor_data = NULL;
		char *appname = NULL;
		struct timeval begin;
		struct timeval end;
		int ret = 0;
		char key[CLIENTID] = {'\0'};
		//gf_log("sh", GF_LOG_INFO, "enter qos_monitor_writev_cbk.");
        priv = this->private;
		client = (client_id_t*) frame->root->trans;
		if (client == NULL) {
			gethostname(key, sizeof(key));
		 } else {
			get_client_id(client->id, key);
		 }
		LOCK(&priv->lock);
		if (priv->metrics != NULL) {
			dict_ref(priv->node_appname);
         	ret = dict_get_str(priv->node_appname, key, &appname);
         	if(ret != 0){
            	dict_unref(priv->node_appname);
            	//goto out;
         	}else{
            	strcpy(key, appname);
            	dict_unref(priv->node_appname);
         	}
			
			dict_ref(priv->metrics);
			ret = dict_get_ptr(priv->metrics, key, (void **)&monitor_data);
			//gf_log("sh", GF_LOG_INFO, "dict_get_ptr fini.");
			if (ret != 0) {
				gf_log("sh", GF_LOG_ERROR, "dict_get_ptr failed.");
			} else {
				monitor_data = (struct qos_monitor_data *)monitor_data;	
				gettimeofday(&monitor_data->write_delay.unwind_at, NULL);
				begin = monitor_data->write_delay.wind_at;
				end = monitor_data->write_delay.unwind_at;
				monitor_data->data_written = monitor_data->data_written + op_ret / KB ;
				monitor_data->write_delay.value = (monitor_data->write_delay.value + time_difference_us(&begin, &end)) / 2;
				/*gf_log("sh", GF_LOG_INFO, "value = %lf", monitor_data->read_delay.value);
				gf_log("sh", GF_LOG_INFO, "value = %lf ms", time_difference_ms(&begin, &end));*/
			}
			data_unref(data_from_ptr((void*)monitor_data));
			dict_unref(priv->metrics);			
			//gf_log("sh", GF_LOG_INFO, "qos_monitor_writev_cbk prepared.");
		} else {
			gf_log("sh", GF_LOG_ERROR, "priv->metrics == NULL.");
		}
out:
		UNLOCK(&priv->lock);

		//gf_log("sh", GF_LOG_INFO, "qos_monitor_writev_cbk unwind start.");
		STACK_UNWIND (frame, op_ret, op_errno, prebuf, postbuf);
		//gf_log("sh", GF_LOG_INFO, "qos_monitor_writev_cbk unwind end.");
        return 0;
}


int32_t
qos_monitor_readv_cbk (call_frame_t *frame,
				 void *cookie,
				 xlator_t *this,
				 int32_t op_ret,
				 int32_t op_errno,
				 struct iovec *vector,
				 int32_t count,
				 struct stat *buf,
				 struct iobref *iobref)
{
	qos_monitor_private_t *priv = NULL;
	client_id_t *client = NULL;
	struct qos_monitor_data *monitor_data = NULL;
	char* appname = NULL;
	struct timeval begin;
	struct timeval end;
	int ret = 0;
    char key[CLIENTID] = {'\0'};
	//gf_log("sh", GF_LOG_INFO, "enter.");
	priv = this->private;
	client = (client_id_t*) frame->root->trans;
	if (client == NULL) {
		gethostname(key, sizeof(key));
	 } else {
		get_client_id(client->id, key);
	 }
	LOCK(&priv->lock);
	if (priv->metrics != NULL) {
		dict_ref(priv->node_appname);
        ret = dict_get_ptr(priv->node_appname, key, &appname);
        if(ret != 0){
            dict_unref(priv->node_appname);
            //goto out;
        }else{
            strcpy(key, appname);
            dict_unref(priv->node_appname);
        }

		dict_ref(priv->metrics);
		ret = dict_get_ptr(priv->metrics, key, (void **)&monitor_data);
		//gf_log("sh", GF_LOG_INFO, "dict_get_ptr fini.");
		if (ret != 0) {
			gf_log("sh", GF_LOG_ERROR, "dict_get_ptr failed.");
		} else {
			monitor_data = (struct qos_monitor_data *)monitor_data;	
			gettimeofday(&monitor_data->read_delay.unwind_at, NULL);
			begin = monitor_data->read_delay.wind_at;
			end = monitor_data->read_delay.unwind_at;
			monitor_data->data_read = monitor_data->data_read + op_ret / KB ;
			monitor_data->read_delay.value = (monitor_data->read_delay.value + time_difference_us(&begin, &end)) / 2;
			/*gf_log("sh", GF_LOG_INFO, "value = %lf", monitor_data->read_delay.value);
			gf_log("sh", GF_LOG_INFO, "value = %lf ms", time_difference_ms(&begin, &end));*/
		}
		data_unref(data_from_ptr((void*)monitor_data));
		dict_unref(priv->metrics);			
		//gf_log("sh", GF_LOG_INFO, "prepared.");
	} else {
		gf_log("sh", GF_LOG_ERROR, "priv->metrics == NULL.");
	}
out:
	UNLOCK(&priv->lock);


	STACK_UNWIND (frame, op_ret, op_errno, vector, count, buf, iobref);

	return 0;
}



int32_t
qos_monitor_readv (call_frame_t *frame,
			 xlator_t *this,
			 fd_t *fd,
			 size_t size,
			 off_t offset)
{
	 
	 qos_monitor_private_t *priv = NULL;
	 client_id_t *client = NULL;
	 struct qos_monitor_data *monitor_data = NULL;
	 char *appname = NULL;
	 int ret = 0;
	 char key[CLIENTID] = {'\0'};
	 //gf_log("sh", GF_LOG_INFO, "enter.");
	 priv = this->private;
	 client = (client_id_t*) frame->root->trans;
	  if (client == NULL) {
		gethostname(key, sizeof(key));
	 } else {
		get_client_id(client->id, key);
	 }
	 LOCK(&priv->lock);
	 //gf_log("sh", GF_LOG_INFO, "lock");
	 if (priv->metrics != NULL) {
		 //gf_log("sh", GF_LOG_INFO, "priv->metrics != NULL.");
		 //??????node??????appname
		 dict_ref(priv->node_appname);
		 ret = dict_get_ptr(priv->node_appname, key, &appname);
		 if(ret != 0){
			dict_unref(priv->node_appname);
		 	//goto out;	 	
		 }else{
			//gf_log("hk", GF_LOG_ERROR, "before copied client_key: %s  app_key: %s",key, appname);
		 	strcpy(key, appname);
			//gf_log("hk", GF_LOG_ERROR, "after copied client_key: %s  app_key: %s",key, appname);
		 	dict_unref(priv->node_appname);
		 }

		 dict_ref(priv->metrics);
		 //gf_log("sh", GF_LOG_INFO, "dict_get_ptr.");
		 ret = dict_get_ptr(priv->metrics, key, (void **)&monitor_data);
		 //gf_log("sh", GF_LOG_INFO, "dict_get_ptr fini.");

		 if (ret != 0) {
			 /*gf_log("sh", GF_LOG_INFO, "monitor_data doesn't exist.");*/
			 monitor_data = CALLOC (1, sizeof(*monitor_data));
			 ERR_ABORT (monitor_data);	
			 _qos_init_monitor_data(monitor_data);
			 ret = dict_set_ptr(priv->metrics, key, (void *)monitor_data);
			 if (ret != 0)
				 gf_log("sh", GF_LOG_ERROR, "dict set failed.");
		 } else { 
			 //gf_log("sh", GF_LOG_INFO, "monitor_data exist.");
			 monitor_data = (struct qos_monitor_data *)monitor_data; 
		 } /* end if monitor_data == NULL */

		 //gf_log("sh", GF_LOG_INFO, "get write_delay.wind_at.");
		 gettimeofday(&monitor_data->read_delay.wind_at, NULL);
		 monitor_data->data_iops++;

		 dict_unref(priv->metrics);
		 //gf_log("sh", GF_LOG_INFO, "qos_monitor_writev prepared.");
	 } else {
		 gf_log("sh", GF_LOG_ERROR, "priv->metrics == NULL.");
	 }
out:
	 UNLOCK(&priv->lock);
	 //gf_log("sh", GF_LOG_INFO, "unlock");
	 
	 //gf_log("sh", GF_LOG_INFO, "start wind.");

	 STACK_WIND (frame,
				 qos_monitor_readv_cbk,
				 FIRST_CHILD(this),
				 FIRST_CHILD(this)->fops->readv,
				 fd,
				 size,
				 offset);
	 
	 //gf_log("sh", GF_LOG_INFO, "end wind.");
	 return 0;
}



int32_t
qos_monitor_writev (call_frame_t *frame,
                 xlator_t *this,
                 fd_t *fd,
                 struct iovec *vector,
                 int32_t count,
                 off_t offset,
                 struct iobref *iobref)
{

		qos_monitor_private_t *priv = NULL;
		client_id_t *client = NULL;
		struct qos_monitor_data *monitor_data = NULL;
		char *appname =NULL;
		int ret = 0;
		
		char key[CLIENTID] = {'\0'};
		//gf_log("sh", GF_LOG_INFO, "enter qos_monitor_writev.");
        priv = this->private;
		client = (client_id_t*) frame->root->trans;
		 if (client == NULL) {
			gethostname(key, sizeof(key));
		 } else {
			get_client_id(client->id, key);
		 } 
		/*gf_log("sh", GF_LOG_INFO, "client_id: %s", key);*/
		LOCK(&priv->lock);
		//gf_log("sh", GF_LOG_INFO, "lock");
		if (priv->metrics != NULL) {
			//gf_log("sh", GF_LOG_INFO, "priv->metrics != NULL.");
		
			//??????node??????appname
		 	dict_ref(priv->node_appname);
         	ret = dict_get_str(priv->node_appname, key, &appname);
         	if(ret != 0){
            	dict_unref(priv->node_appname);
            	//goto out;
         	}else{
            	strcpy(key, appname);
            	dict_unref(priv->node_appname);
         	}	
			
			dict_ref(priv->metrics);

			//gf_log("sh", GF_LOG_INFO, "dict_get_ptr.");
			ret = dict_get_ptr(priv->metrics, key, (void **)&monitor_data);
			//gf_log("sh", GF_LOG_INFO, "dict_get_ptr fini.");

			if (ret != 0) {
				
				//gf_log("sh", GF_LOG_INFO, "monitor_data doesn't exist.");
				monitor_data = CALLOC (1, sizeof(*monitor_data));
				ERR_ABORT (monitor_data);  
				_qos_init_monitor_data(monitor_data);
				ret = dict_set_ptr(priv->metrics, key, (void *)monitor_data);
				if (ret != 0)
					gf_log("sh", GF_LOG_ERROR, "dict set failed.");
			} else {
				
				//gf_log("sh", GF_LOG_INFO, "monitor_data exist.");
				monitor_data = (struct qos_monitor_data *)monitor_data;	
			} /* end if monitor_data == NULL */

			//gf_log("sh", GF_LOG_INFO, "get write_delay.wind_at.");
			gettimeofday(&monitor_data->write_delay.wind_at, NULL);
			monitor_data->data_iops++;

			dict_unref(priv->metrics);
			//gf_log("sh", GF_LOG_INFO, "qos_monitor_writev prepared.");
		} else {
			gf_log("sh", GF_LOG_ERROR, "priv->metrics == NULL.");
		}
out:
		UNLOCK(&priv->lock);
		
        //gf_log("sh", GF_LOG_INFO, "start wind.");
        STACK_WIND (frame,
                    qos_monitor_writev_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->writev,
                    fd,
                    vector,
                    count,
                    offset,
                    iobref);
		//gf_log("sh", GF_LOG_INFO, "end wind.");
        return 0;
}


int32_t
init (xlator_t *this)
{
        dict_t *options = NULL;
        char *includes = NULL, *excludes = NULL;
        qos_monitor_private_t *priv = NULL;
		int32_t interval;
		int ret = -1;
		char *redis_host;
		char *publish_channel;
		int32_t redis_port, redis_publish_interval;

		DISCONNECT_FLAG = 0;

        if (!this)
                return -1;

        if (!this->children || this->children->next) {
                gf_log (this->name, GF_LOG_ERROR,
                        "qos_monitor translator requires one subvolume");
                return -1;
        }
        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = CALLOC (1, sizeof(*priv));
        ERR_ABORT (priv);  
		
		priv->publisher = CALLOC (1, sizeof(*(priv->publisher)));
        ERR_ABORT (priv->publisher);  

		priv->reconnect_times = 0;
		priv->reconnect_succed = 0;

		//jy-test
		pthread_mutex_init (&priv->publisher->qlock, NULL);
		pthread_cond_init (&priv->publisher->notifier, NULL);

		priv->metrics = dict_new();
		ERR_ABORT (priv->metrics);  
		
		priv->node_appname = dict_new();
		ERR_ABORT (priv->node_appname);  
		


        options = this->options;
		interval = data_to_int32 (dict_get (options, "monitor-interval"));
		if (interval == -1)
			interval = INTERNAL;
		redis_host = data_to_str (dict_get (options, "redis-host"));
		publish_channel = data_to_str (dict_get (options, "publish-channel"));
		redis_port = data_to_int32 (dict_get (options, "redis-port"));
		if (redis_port == -1)
			redis_port = PORT;
		redis_publish_interval = data_to_int32 (dict_get (options, "redis-publish-interval"));
		if (redis_publish_interval == -1)
			redis_publish_interval = REDIS_INTERVAL;
		REDIS_INTERVAL = redis_publish_interval;
        LOCK_INIT (&priv->lock);
		
		if (interval != 0)
			priv->qos_monitor_interval = interval;
		else
			priv->qos_monitor_interval = 1;
		
		// redis???????????????????????????
		if (redis_host) {
			priv->publisher->redis_host = CALLOC (1, strlen(redis_host));
			ERR_ABORT(priv->publisher->redis_host);
			strcpy(priv->publisher->redis_host, redis_host);
		} else {
			priv->publisher->redis_host = CALLOC (1, strlen(HOST));
			ERR_ABORT(priv->publisher->redis_host);
			strcpy(priv->publisher->redis_host, HOST);
		}
		
		if (publish_channel) {
			priv->publisher->channel = CALLOC (1, strlen(publish_channel));
			ERR_ABORT(priv->publisher->channel);
			strcpy(priv->publisher->channel, publish_channel);
		} else {
			priv->publisher->channel = CALLOC (1, strlen(CHANNEL));
			ERR_ABORT(priv->publisher->channel);
			strcpy(priv->publisher->channel, CHANNEL);
		}
		
		priv->publisher->redis_port = redis_port;
		
		gf_log (this->name, GF_LOG_INFO,
                        "interval = %d, redis-host: %s, publish-channel: %s, redis-port: %d", 
						priv->qos_monitor_interval, priv->publisher->redis_host, priv->publisher->channel, priv->publisher->redis_port);
		
		ret = redis_init(priv->publisher);
		if (!ret)
		{
			gf_log(this->name, GF_LOG_ERROR,
				   "Redis publisher init failed.");
		} else {
			gf_log(this->name, GF_LOG_INFO,
				   "Redis publisher inited.");
		}
		
		ret = redis_connect(priv->publisher);
		if (!ret)
		{
			gf_log(this->name, GF_LOG_ERROR,
				   "Redis connect failed.");
		} else {
			gf_log(this->name, GF_LOG_INFO,
					"Redis connected.");
		}       
		
		//??????????????????node???app???????????????
		//subscribe("monitor", priv);
		//??????redis
		redis_syncconnect(priv->publisher);
		ret = pthread_create( &(priv->publisher->sub_pthread), NULL, &syncsubscribe, priv);                                                       
        if(ret != 0){
			gf_log("monitor", GF_LOG_ERROR, " sub_pthread failed");
		}else{
			gf_log("monitor", GF_LOG_ERROR, " sub_pthread success");
        }
		/* Set this translator's inode table pointer to child node's pointer. */
        //this->itable = FIRST_CHILD (this)->itable;
        
		this->private = priv;
		if (priv->qos_monitor_interval > 0) {
			priv->monitor_thread_running = 1;
			priv->monitor_thread_should_die = 0;
			ret = pthread_create(&priv->monitor_thread, NULL,
								   (void *)&_qos_monitor_thread, this);
			if (ret) {
				priv->monitor_thread_running = 0;
				gf_log(this ? this->name : "qos-monitor", GF_LOG_ERROR,
					   "Failed to start thread"
					   "in init. Returning %d",
					   ret);
				goto out;
			}
		}
		this->private = priv;
		
		gf_log (this->name, GF_LOG_INFO,
                        "qos_monitor translator loaded.");
		return ret;

out:
	qos_private_destroy(priv);
    return ret;
}

void
fini (xlator_t *this)
{
        qos_monitor_private_t *priv = NULL;

        if (!this)
                return;

        priv = this->private;
		
		qos_private_destroy(priv);  

		this->private = NULL;
        gf_log (this->name, GF_LOG_NORMAL,
                "qos_monitor translator unloaded");
        return;
}


struct xlator_fops fops = {
        .writev      = qos_monitor_writev,
        .readv       = qos_monitor_readv,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
		{ .key  = {"monitor-interval", "interval"},
          .type = GF_OPTION_TYPE_INT,
        },
		{ .key  = {"redis-host", "host"},
          .type = GF_OPTION_TYPE_STR,
        },
		{ .key  = {"publish-channel", "channel"},
          .type = GF_OPTION_TYPE_STR,
        },
		{ .key  = {"redis-port", "port"},
          .type = GF_OPTION_TYPE_INT,
        },
        { .key  = {"redis-publish-interval", "publish-interval"},
          .type = GF_OPTION_TYPE_INT,
        },
        { .key  = {NULL} },
};
