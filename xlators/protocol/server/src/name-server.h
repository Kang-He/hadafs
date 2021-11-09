#ifndef _NAME_SERVER_H
#define _NAME_SERVER_H

#include <hiredis/hiredis.h>

#include "hadafs.h"
#include "common-utils.h"
#include "xlator.h"

#define MAX_PATH_LEN 1024
#define MAX_CONTAINER_CMD_LEN 1088
#define MAX_CMD_LEN 4096
#define NSE_HOSTNAME_LEN 32
#define RS_PORT 6379
#define NAME_SERVER "127.0.0.1"

#define RS_TRANS_START "multi"
#define RS_TRANS_FINISH "exec"

#define UPDATE_MODE 0x0040
#define UPDATE_UID 0x0020
#define UPDATE_GID 0x0010
#define UPDATE_SIZE 0x0008
#define UPDATE_CTIME 0x0004
#define UPDATE_MTIME 0x0002
#define UPDATE_ATIME 0x0001

typedef enum {
	NSE_CONTAINER,
	NSE_OBJECT,
} nse_type_t;

typedef enum {
	NSE_UPDATE,
	NSE_CREATE,
} nse_update_t;

typedef enum {
	NSE_LOCAL,
	RDC_MOVING,
	RDC_MOVED,
	RDC_DELTED,
} nse_location_t;

typedef enum {
	RDC_INIT,
	RDC_CONECTED,
	RDC_DISCON
} rdc_status_t;

typedef enum {
	VMP_VAL_INDEX, /* 0 */
	SID_VAL_INDEX,
	SOFFSET_VAL_INDEX, 
	LHOST_VAL_INDEX,
	LNO_VAL_INDEX,
	LOCATION_VAL_INDEX,
	PPATH_VAL_INDEX,
	ONO_VAL_INDEX,
	MODE_VAL_INDEX,
	UID_VAL_INDEX,
	GID_VAL_INDEX,
	SIZE_VAL_INDEX,
	ATIME_VAL_INDEX,
	MTIME_VAL_INDEX,
	CTIME_VAL_INDEX,
	MAX_INDEX,
} nse_redis_index_t;


struct _rd_context {
	redisContext  *rdc_rc;
	char *rdc_addr;
	int32_t rdc_port;
        int32_t rdc_dbnum;
	struct timeval rdc_timeout;
	rdc_status_t rdc_status;
	gf_lock_t *rdc_lock;
};

typedef struct _rd_context rd_context_t;

extern rd_context_t *rd_connect (char *ns_addr, int ns_port);
extern int32_t rd_disconnect (rd_context_t *rdc);
extern int32_t ns_isexist_object (rd_context_t *rdc, object_t *obj);
extern int32_t ns_lookup_object(rd_context_t *rdc, object_t *obj);
extern int32_t ns_set_object (rd_context_t *rdc, object_t *obj);
extern int32_t ns_update_object (rd_context_t *rdc, object_t *obj, int16_t updatebits);
extern int32_t ns_del_object(rd_context_t *rdc, object_t *obj);

#endif
