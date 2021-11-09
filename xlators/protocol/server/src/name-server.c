#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "logging.h"
#include "hadafs.h"
#include "common-utils.h"
#include "name-server.h"


rd_context_t *
rd_db_init (char *ns_addr, int32_t ns_port)
{
	rd_context_t *rdc = NULL;
	rdc = calloc(1, sizeof(rd_context_t));
	if(rdc == NULL) {
		return NULL;
	}

	rdc->rdc_rc = NULL;
	rdc->rdc_addr = strdup(ns_addr);
	rdc->rdc_port = ns_port;
	rdc->rdc_timeout.tv_sec =1;	/* 1.5 seconds */
	rdc->rdc_timeout.tv_usec =500000;/* 1.5 seconds */
	rdc->rdc_status = RDC_INIT;

	//LOCK_INIT (&rdc->rdc_lock);

	return rdc;
}

int32_t
rd_db_destroy (rd_context_t *rdc)
{
	if (rdc == NULL)
		return 0;

	LOCK_DESTROY(rdc->rdc_lock);
	redisFree(rdc->rdc_rc);
	free(rdc);

	return 0;
}

rd_context_t *
rd_connect (char *db_addr, int db_port)
{
	rd_context_t *rdc = NULL;

	rdc = rd_db_init(db_addr, db_port);
	if(rdc == NULL)
		return rdc;

	/* first connect addr */
	if(rdc->rdc_addr == NULL || rdc->rdc_port == 0 ){
		gf_log ("name-server", GF_LOG_ERROR,
				"init before connected to name server port %d failed ",
				 rdc->rdc_port);
		return NULL;
	}
	rdc->rdc_rc = redisConnect(rdc->rdc_addr, rdc->rdc_port);
	if(rdc->rdc_rc->err) {
		redisFree(rdc->rdc_rc);
		
		/* then connect addr
 		 * wait for 60 seconds for backup server active
 		 */
		sleep(60);
		rdc->rdc_rc = redisConnect(rdc->rdc_addr, rdc->rdc_port);
		if(rdc->rdc_rc->err) {
			gf_log ("name-server", GF_LOG_NORMAL,
				"connected to name server %s %d failed twice",
				rdc->rdc_addr, rdc->rdc_port);
			FREE(rdc);
			return NULL;
		}
	}
	rdc->rdc_status = RDC_CONECTED;
	gf_log ("name-server", GF_LOG_NORMAL,
		"connected to name server %s %d", rdc->rdc_addr, rdc->rdc_port);
	return rdc;
}

int32_t 
rd_reconnect (rd_context_t *rdc)
{
	if(rdc == NULL)
		return -1;

	/* first connect addr */
	rdc->rdc_rc = redisConnect(rdc->rdc_addr, rdc->rdc_port);
	if(rdc->rdc_rc->err) {
		redisFree(rdc->rdc_rc);
		
		/* then connect addr
 		 * wait for 60 seconds for backup server active
 		 */
		sleep(60);
		rdc->rdc_rc = redisConnect(rdc->rdc_addr, rdc->rdc_port);
		if(rdc->rdc_rc->err) {
			gf_log ("name-server", GF_LOG_NORMAL,
				"reconnected to name server %s %d failed twice",
				rdc->rdc_addr, rdc->rdc_port);
			FREE(rdc);
			return -1;
		}
	}
	gf_log ("name-server", GF_LOG_NORMAL, "reconnected to name server %s %d",
		rdc->rdc_addr, rdc->rdc_port);
	rdc->rdc_status = RDC_CONECTED;
	return 0;
}

int32_t
rd_disconnect (rd_context_t *rdc)
{
	if(rdc == NULL)
		return -1;

	rd_db_destroy(rdc);
	return 0;
}

redisReply *
ns_send_rediscmd(rd_context_t *rdc, char *redis_cmd, int retry_count)
{
	redisReply *re = NULL;
	int i;
	if (retry_count == 0)
		retry_count = 1;

	re = (redisReply *)redisCommand(rdc->rdc_rc, redis_cmd);
	if(rdc->rdc_rc->err & (REDIS_ERR_IO | REDIS_ERR_EOF)) {
		/* redis may need reconnecting */
		for (i = 0; i < retry_count; i++) {
			if(rd_reconnect(rdc) != 0)
				return NULL;

			re = (redisReply *)redisCommand(rdc->rdc_rc, redis_cmd);
			break;
		}
	}
	return re;
}

/*
 * -1: error
 * 0: not found
 * 1: found
 * 2: parent dir not found
 */
int32_t ns_lookup_object(rd_context_t *rdc, object_t *obj)
{
	char redis_cmd[MAX_CMD_LEN] = "";
	char object_key[1024] = "\0";
	redisReply *re = NULL;
	char *dir_name = NULL;
	int i, found = -1;
	
	if(rdc == NULL || obj == NULL)
		return NULL;

	dir_name = strdup(obj->path);
	sprintf(redis_cmd, "exists d:%s", dirname(dir_name));
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
	if(re == NULL) {
		gf_log("name-server", GF_LOG_ERROR, "get parent error when lookup %s",
				obj->path);
		free(dir_name);
		return -1;
	}
	if(re->type == REDIS_REPLY_INTEGER){
		if(re->integer == 0){
			gf_log("name-server",GF_LOG_ERROR,
					"dir %s not exsit while open object %s",
					dir_name, obj->path);
			free(dir_name);
			freeReplyObject(re);
			return 2;
		}
	}


	found = ns_isexist_object (rdc, obj);
        if(found != 1) {
                return 0;
        }
	sprintf(object_key, "f:%s",obj->path);
	sprintf(redis_cmd, "hmget %s mntpnt sid soffset lhost lno location ppath ono mode uid gid size atime mtime ctime", object_key);
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
	if(re == NULL) {
		gf_log("name-server", GF_LOG_ERROR, "error when lookup %s",
			obj->path);
		return -1;
	}

	if(re->type == REDIS_REPLY_ARRAY) {
		/*
		 * lookup enty in redis success, transform the enty
		 * to nse 
		 */
		if(re->elements == MAX_INDEX && re->element[LHOST_VAL_INDEX]->str != NULL) {
			obj->vmp = strdup(re->element[VMP_VAL_INDEX]->str);
			obj->lhost = strdup(re->element[LHOST_VAL_INDEX]->str);
			obj->lno = atoll(re->element[LNO_VAL_INDEX]->str);
			obj->location = atoi(re->element[LOCATION_VAL_INDEX]->str);
			obj->ppath = strdup(re->element[PPATH_VAL_INDEX]->str);
 			obj->ono = atoll(re->element[ONO_VAL_INDEX]->str); 			
			obj->mode = atoi(re->element[MODE_VAL_INDEX]->str);
			obj->uid = atoi(re->element[UID_VAL_INDEX]->str);
			obj->gid = atoi(re->element[GID_VAL_INDEX]->str);
			obj->size = atoll(re->element[SIZE_VAL_INDEX]->str);
			obj->atime = atoll(re->element[ATIME_VAL_INDEX]->str);
			obj->mtime = atoll(re->element[MTIME_VAL_INDEX]->str);
			obj->ctime = atoll(re->element[CTIME_VAL_INDEX]->str);
			found = 1;
		} else if(re->elements > 0){
			gf_log("name-server", GF_LOG_ERROR, "get %d values when lookup %s,\
				so i think this key illegal delete it",
				re->elements, obj->path);
			ns_del_object(rdc, obj);
			found = 0;
		} else
			found = 0; 
	} else 
		found = 0;

	if(dir_name != NULL)	
		free(dir_name);

	freeReplyObject(re);

	return found;
}

/*
 * -1: error
 * 0: not found
 * 1: found
 */
int32_t
ns_isexist_object (rd_context_t *rdc, object_t *obj)
{
        char redis_cmd[MAX_CMD_LEN] = "";
	char object_key[1024] = "";
        redisReply *re = NULL;
        int found = -1;

        if(rdc == NULL || obj == NULL)
                return -1;
	
	sprintf(object_key, "f:%s", obj->path);
        sprintf(redis_cmd, "exists %s", object_key);
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
        if(re == NULL) {
        	freeReplyObject(re);
                return -1;
        }

        if(re->type == REDIS_REPLY_INTEGER) {
                if(re->integer ) {
                        found = 1;
                } else {
                        found = 0;
		}
        }
        else
                found = 0;

        freeReplyObject(re);

        return found;

}

int32_t
ns_set_object (rd_context_t *rdc, object_t *obj)
{
	int ret = 0;
	char redis_cmd[MAX_CMD_LEN] = "\0";
	char redis_cmd1[MAX_CMD_LEN] = "\0";
	char object_key[1024] = "\0";
	char *dir_name = NULL;
#ifdef YUT201812
	redisReply *re = NULL;
#else
	redisReply **re = NULL;
#endif
	

	
	if(rdc == NULL || obj == NULL)
		return -1;
	
	sprintf(object_key, "f:%s",obj->path);
	sprintf(redis_cmd, "hmset %s mntpnt %s sid %s soffset %u lhost %s lno %llu \
location %u ppath %s ono %llu mode %d uid %d gid %d size %ld \
atime %ld mtime %ld ctime %ld",
			object_key,
			obj->vmp,
			obj->sid,
			obj->soffset,
			obj->lhost,
			obj->lno,
			obj->location,
			obj->ppath,
			obj->ono,
			obj->mode,
			obj->uid,
			obj->gid,
			obj->size,
			obj->atime,
			obj->mtime,
			obj->ctime);
	

	#ifdef YUT201812
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
	if(re == NULL || 
		!(re->type == REDIS_REPLY_STATUS && !strcasecmp(re->str, "OK"))){
		gf_log ("name-server", GF_LOG_ERROR,
				"Set obj in hash for %s failed[%s]",
				obj->path, re == NULL?"reply NULL":re->str);
		ret = -1;
		goto out;
	}
#endif
	dir_name = strdup(obj->path);
	if(dir_name == NULL) {
		gf_log ("name-server", GF_LOG_ERROR, "Out of memory");
		ret = -1;
		goto out;
	}
	sprintf(redis_cmd1, "sadd d:%s:children %s:%s",dirname(dir_name), object_key, obj->lhost);

#ifndef YUT201812
	int i;
	redisAppendCommand(rdc->rdc_rc,redis_cmd);
	redisAppendCommand(rdc->rdc_rc,redis_cmd1);
	re = CALLOC(2, sizeof(redisReply*));
	if(re == NULL) {
		gf_log ("name-server", GF_LOG_ERROR, "Out of memory");
		ret = -1;
		goto out;
	}
	for(i=0; i<2; i++){
		if(redisGetReply(rdc->rdc_rc, (void *)&re[i]) != REDIS_OK || (re[i] == NULL)) {
			gf_log("name-server", GF_LOG_ERROR, "redis %s get reply failed %s", 
					i==0 ? redis_cmd:redis_cmd1, 
					re[i]!=NULL ? re[i]->str:"NULL");
			ret = -1;
			goto out;
		}
	}

	if(!(re[0]->type == REDIS_REPLY_STATUS && !strcasecmp(re[0]->str, "OK"))){
		gf_log ("name-server", GF_LOG_ERROR,
				"Set obj in hash for %s failed[%s]",
				obj->path, re[0] == NULL?"reply NULL":re[0]->str);
		ret = -1;
		goto out;
	}

	if(!(re[1]->type == REDIS_REPLY_INTEGER && re[1]->integer == 1)){

		gf_log ("name-server", GF_LOG_ERROR, "return type is %d\n", re[1]->type);
		int j=0;
		if (re[1]->element != NULL) {
			for (j = 0; j < re[1]->elements; j++)
				gf_log ("name-server", GF_LOG_ERROR, " TTT %u %s\n",j, re[1]->element[j]->str);
		}
		gf_log ("name-server", GF_LOG_ERROR,
				"Set obj in dir for %s failed",
				obj->path);
	}
#else
	re = (redisReply *)redisCommand(rdc->rdc_rc, redis_cmd);
	if(re == NULL ||
			!(re->type == REDIS_REPLY_INTEGER && re->integer == 1)){
		gf_log ("name-server", GF_LOG_ERROR,
				"Set obj in dir for %s failed[%s]",
				obj->path, re == NULL?"reply NULL":re->str);
		ret = -1;
	}
#endif
out:	
#ifdef YUT
	if(re != NULL)
		freeReplyObject(re);
#else
	if(re != NULL){
		for(i = 0; i < 2; i++) {
			if(re[i] != NULL)
				freeReplyObject(re[i]);
		}
		FREE(re);
	}
#endif
	if(dir_name != NULL)
		free(dir_name);

	return ret;
}

int32_t
ns_update_object (rd_context_t *rdc, object_t *obj, int16_t updatebits)
{
	int ret = 0;
	char redis_cmd[MAX_CMD_LEN] = "\0";
	char object_key[1024] = "\0";
	char attr_tmp[128] = "\0";
	redisReply *re = NULL;

	if(rdc == NULL || obj == NULL)
		return -1;

	ret = ns_isexist_object (rdc, obj);
	if(ret != 1) {
		gf_log ("name-server", GF_LOG_ERROR, "%s is not exist", obj->path);
		return -1;
	}

	sprintf(object_key, "f:%s",obj->path);
	sprintf(redis_cmd, "hmset %s",object_key);
	if(updatebits & UPDATE_MODE) {
		sprintf(attr_tmp, " mode %d", obj->mode);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_UID) {
		sprintf(attr_tmp, " uid %d", obj->uid);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_GID) {
		sprintf(attr_tmp, " gid %d", obj->gid);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_SIZE) {
		sprintf(attr_tmp, " size %ld", obj->size);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_CTIME) {
		sprintf(attr_tmp, " ctime %ld", obj->ctime);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_MTIME) {
		sprintf(attr_tmp, " mtime %ld", obj->mtime);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}
	if(updatebits & UPDATE_ATIME) {
		sprintf(attr_tmp, " atime %ld", obj->atime);
		strcat(redis_cmd, attr_tmp);
		attr_tmp[0] = '\0';
	}

	re = ns_send_rediscmd(rdc, redis_cmd, 1);
	if(re == NULL) {
		ret = -1;
		goto out;
	}
	if(!(re->type == REDIS_REPLY_STATUS && !strcasecmp(re->str, "OK"))){
		gf_log ("name-server", GF_LOG_ERROR, 
			"update %s failed[%s] with cmd[%s]", 
			obj->path, re->str, redis_cmd);
		ret = -1;
	} else 
		ret = 0;
out:
	if(re != NULL)
		freeReplyObject(re);

	return ret;
}

int32_t
ns_del_object(rd_context_t *rdc, object_t *obj)
{
	char redis_cmd[MAX_CMD_LEN] = "";
	char redis_cmd1[MAX_CMD_LEN] = "";
	char object_key[1024] = "";
	char *dir_name = NULL;
#ifdef YUT201812
	redisReply *re = NULL;
#else
	redisReply **re = NULL;
#endif

	int ret = 0;

	if(rdc == NULL || obj == NULL)
		return -1;

	/* del enty in hash list */
	sprintf(object_key, "f:%s",obj->path);
	sprintf(redis_cmd, "del %s", object_key);

#ifdef YUT201812
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
	if(re == NULL ||
                !(re->type == REDIS_REPLY_INTEGER && re->integer == 1)){
                gf_log ("name-server", GF_LOG_ERROR,"del obj %s failed[%s]",
			obj->path, re == NULL?"reply NULL":re->str);
                ret = -1;
		goto out;
        }
#endif
        dir_name = strdup(obj->path);
	if(dir_name == NULL) {
                gf_log ("name-server", GF_LOG_ERROR,"Out of memory");
		ret = -1;
		goto out;
	}
	dir_name = dirname(dir_name);
	sprintf(redis_cmd1, "srem d:%s:children %s:%s", dir_name,object_key, obj->lhost);
#ifndef YUT201812
	int i;
	redisAppendCommand(rdc->rdc_rc,redis_cmd);
	redisAppendCommand(rdc->rdc_rc,redis_cmd1);
	re = calloc(sizeof(redisReply*) , 2);
	for(i=0; i<2; i++){
		assert(redisGetReply(rdc->rdc_rc, (void *)&re[i]) == REDIS_OK);
		assert(re[i] != NULL);
	}
	if(!(re[0]->type == REDIS_REPLY_INTEGER && re[0]->integer == 1)){
		gf_log ("name-server", GF_LOG_ERROR,"del obj %s failed[%s]",
				obj->path, re[0] == NULL?"reply NULL":re[0]->str);
		ret = -1;
		goto out;
	}
	if(!(re[1]->type == REDIS_REPLY_INTEGER && re[1]->integer == 1)){
		gf_log ("name-server", GF_LOG_ERROR,"remove obj %s from dir failed[%s]",
				obj->path, re[1] == NULL?"reply NULL":re[1]->str);
		ret = -1;
	}
#else
	re = ns_send_rediscmd(rdc, redis_cmd, 1);
        if(re == NULL ||
                !(re->type == REDIS_REPLY_INTEGER && re->integer == 1)){
                gf_log ("name-server", GF_LOG_ERROR,"remove obj %s from dir failed[%s]",
			obj->path, re == NULL?"reply NULL":re->str);
                ret = -1;
        }
#endif
out:
	if(re != NULL){
		for(i=0;i<2;i++) {
			if(re[i] == NULL)
				freeReplyObject(re[i]);
		}
		free(re);
	}
	if(dir_name != NULL)
		free(dir_name);

	return ret;
}

