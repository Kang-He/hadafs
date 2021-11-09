#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "hadafs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "list.h"
#include "compat.h"
#include "compat-errno.h"
#include "common-utils.h"
#include "call-stub.h"
#include "hadafs_ioctl.h"
#include "defaults.h"
#include <semaphore.h>
//#include "statedump.h"

#define THREAD_COUNT 4
#define MC_MIN_THREADS 1
#define MC_MAX_THREADS 16
#define MC_WINDOW_SIZE 10485760000 /* 10000MB */
#define MC_SPLIT_COUNT 4  /*  cache request count before wind */
#define LOG_SIZE 17301504 /* (1024+32)*16384 */
#define DEFAULT_LOG_PATH DATADIR"log/memcache.log"
//#define USLEEP 1

typedef struct list_head list_head_t;
struct mc_conf;
struct mc_page;
struct mc_file;
struct worker_arg;
uint64_t g_generation = 0;

typedef struct mc_file {
	size_t       window_conf;
	uint64_t       window_current;
	uint64_t     write_size;
	int32_t      refcount;
	int32_t      cache_type;   /* 0 no cache enable, 1 write behind enable, 3 flush behind enable */
	int32_t      offset_expected;
	int32_t      unfinished_request;
	int32_t      disabled;
	int32_t      op_ret;
	int32_t      op_errno;
	uint64_t     gen;
	list_head_t  request;
	fd_t        *fd;
	gf_lock_t    lock;
	xlator_t    *this;
}mc_file_t;


typedef struct mc_request {
	list_head_t  list;
	call_stub_t *stub;
	size_t       write_size;
	int32_t      refcount;
	mc_file_t   *file;
	/* 
         * 0 for unwind after received reqs from upper layer
         * 1 unwind when received from cbks from lower layer
         */
	int32_t unwind_mark; 

} mc_request_t;

struct mc_conf {
	uint64_t     window_size[MC_MAX_THREADS];
	uint64_t     cached_size[MC_MAX_THREADS];
	gf_boolean_t enable_O_SYNC;
	gf_boolean_t write_behind;
	gf_boolean_t flush_behind;
	pthread_t    write_worker;
	pthread_mutex_t	lock;
	int32_t		curr_count;
		/* logfile map to memory */
	void         *logmmap_start;
	char	     *logfile;
	struct worker_arg  **workers;
	int32_t  thread_count;


};
typedef struct mc_conf mc_conf_t;
struct worker_arg {
	int         thread_id;
	mc_conf_t *wa_conf;
	pthread_t thread;
	pthread_cond_t cond;
	gf_lock_t mutex;
	struct list_head wait_reqs;
	uint32_t wait_count;
};
typedef struct worker_arg mc_worker_t;
typedef struct mc_local {
	int32_t         flags;
	int32_t         mcflags;
	struct mc_file *file;
	mc_request_t   *request;
	char	       **vec_buf;
	uint32_t	vec_count;
	struct iobref  *iobref;
	int             op_ret;
	int             op_errno;
	call_frame_t   *frame;
	call_frame_t   *origin_frame;
	int32_t         reply_count;
	mode_t		mode;
} mc_local_t;


typedef struct mc_page mc_page_t;

void mc_file_ref (mc_file_t *file);

static void *
mc_process_queue (void *data);

ssize_t
mc_sync (call_frame_t *frame, mc_file_t *file, list_head_t *winds);

ssize_t
__mc_mark_winds (list_head_t *list, list_head_t *winds,
		char wind_all, char enable_trickling_writes);

/* 	mmap LOG_FILE to memory		*/
void *  
mc_map(int size, char *logfile){
        int fd;
        void *p;
        fd = open(logfile, O_RDWR|O_CREAT|O_TRUNC, 0644);
        if (fd < 0) {
                perror("open test");
                exit(1);
        }
	lseek(fd, size-1, SEEK_SET);
        write(fd, "0", 1);
        p = mmap(NULL, size, PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) {
                perror("mmap");
                exit(1);
        }
        close(fd);
        return p;
}
/*	record file's sync size to *start ,point to logfile	
 *	path :file path
 *	current :file size leave to sync 		*/
int 
mc_filelog(char *path, char *current, void *start, int complete){
        int i, offset;
        char *p, *q;
        int size1 = 1024;
        int size2 = 32;
	int loop;
	char clean_size1[1024] = {0};
	char clean_size2[32] = {0};
        
	loop = LOG_SIZE/(size1+size2);
	p = start;
        q = p;
        for (i=0; i<loop; i++){
                if(strncmp(q, path, strlen(path))!=0)
                        q = q+size1+size2;
                else
                        break;
        }
	//gf_log("XIAOW", GF_LOG_TRACE, "path is %s loop is %d", path, i);
        if(i != loop ){
		if (!complete){
			q=q+size1;
			strcpy(q, current);
			strcat(q, "\n");
		}
		else{
			strncpy(q, clean_size1, size1);
			q=q+size1;
			strncpy(q, clean_size2, size2);
		}
        }else{
                if (!complete){
			while(strncmp(p, "/", 1)==0)
				p = p+size1+size2;
			strcpy(p, path);
			p = p+size1;
			strcpy(p, current);
			strcat(p, "\n");
		}
        }
        return 0;

}
#ifndef CRC32
static const unsigned long crctab[256] = {
  0x0,
  0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B,
  0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6,
  0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
  0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
  0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F,
  0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A,
  0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
  0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
  0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033,
  0xA4AD16EA, 0xA06C0B5D, 0xD4326D90, 0xD0F37027, 0xDDB056FE,
  0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
  0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4,
  0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077, 0x30476DC0,
  0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5,
  0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
  0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07,
  0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C,
  0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
  0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
  0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B,
  0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698,
  0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D,
  0x94EA7B2A, 0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
  0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
  0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
  0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80,
  0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
  0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A,
  0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629,
  0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C,
  0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
  0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
  0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65,
  0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8,
  0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
  0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2,
  0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71,
  0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74,
  0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
  0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
  0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A,
  0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087,
  0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
  0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D,
  0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679, 0xC1683BCE,
  0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
  0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
  0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
  0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662,
  0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF,
  0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
};

inline
unsigned long crc32(  const void* buffer,
              unsigned long length,
              unsigned long crc)
{
      const unsigned char* cp = (const unsigned char*)buffer;

      while (length--)
        crc = (crc << 8) ^ crctab[((crc >> 24) ^ *(cp++)) & 0xFF];

      return crc;
}

#endif
void
compute_checksum_forward (char *buf, size_t size, uint32_t *checksum)
{
        int  ret = -1;
        char *checksum_buf = NULL;

        checksum_buf = (char *)(checksum);

        for (ret = 0; ret < (size - 4); ret += 4) {
                checksum_buf[0] ^= (buf[ret]);
                checksum_buf[1] ^= (buf[ret + 1] << 1) ;
                checksum_buf[2] ^= (buf[ret + 2] << 2);
                checksum_buf[3] ^= (buf[ret + 3] << 3);
        }

        for (ret = 0; ret <= (size % 4); ret++) {
                checksum_buf[ret] ^= (buf[(size - 4) + ret] << ret);
        }
        
        return;
}

uint32_t
iov_checksum (const struct iovec *vector, int count)
{
        int i;
        uint32_t checksum=0;

        for (i = 0; i < count; i++) {
                compute_checksum_forward(vector[i].iov_base,vector[i].iov_len,&checksum);
        }

        return checksum;
}

int
__mc_workers_scale (mc_conf_t *conf, mc_worker_t **wrk)
{
	pthread_t thread;
	int ret = 0;
	int i; 


	for(i = 0; i < conf->thread_count; i++){
		wrk[i] = CALLOC (1, sizeof (mc_worker_t));
		wrk[i]->wa_conf = conf;
		wrk[i]->thread_id = i;
		INIT_LIST_HEAD (&wrk[i]->wait_reqs);
		LOCK_INIT(&wrk[i]->mutex);
		pthread_cond_init(&wrk[i]->cond, NULL);
		ret = pthread_create (&wrk[i]->thread, NULL, mc_process_queue, wrk[i]);
		if (ret == 0) {
			conf->curr_count++;
			gf_log ("mem-cache", GF_LOG_DEBUG,
					"scaled threads to %d.",
					conf->curr_count);
		} else {
			free(wrk[i]);
			break;
		}
	}
}
mc_file_t *
mc_file_create (xlator_t *this, fd_t *fd)
{
	mc_file_t *file = NULL;
	mc_conf_t *conf = this->private;

	file = CALLOC (1, sizeof (*file));
	if (file == NULL) {
		goto out;
	}
	//gf_log_dump_backtrace("in file create");
	INIT_LIST_HEAD (&file->request);

	/*
	   fd_ref() not required, file should never decide the existance of
	   an fd, the fop such as writev,flush decide.
	   */
	file->fd= fd;
	file->this = this;
	file->window_conf = conf->window_size;
	file->unfinished_request = 0;
	file->disabled = 0;
    	file->refcount = 0;
	file->window_current = 0;
	file->write_size = 0;
	file->gen = g_generation++;
    LOCK_INIT(&file->lock);

    mc_file_ref(file);

	fd_ctx_set (fd, this, (uint64_t)(long)file);

out:
	return file;
}

void
__mc_file_ref (mc_file_t *file)
{
	++file->refcount;
}

void
mc_file_ref (mc_file_t *file)
{
	LOCK (&file->lock);
	{
		__mc_file_ref(file);
	}
	UNLOCK (&file->lock);
}

int32_t
__mc_file_unref (mc_file_t *file)
{
	return --file->refcount;
}

void
mc_file_unref (mc_file_t *file)
{
	int free_or_not = 0;

	LOCK (&file->lock);
	{
		if(!__mc_file_unref(file))
			free_or_not = 1;
	}
	UNLOCK (&file->lock);
	if(free_or_not == 1) {
		//gf_log_dump_backtrace("in free unref");
		gf_log ("xiaow", GF_LOG_ERROR, "file pointer is %p lock %p path is %s", file, &file->lock, file->fd->object->path); 
        	LOCK_DESTROY (&file->lock);
		//FREE(file);
    }
}

void
mc_file_destroy (mc_file_t *file)
{

	mc_file_unref(file);

	return;
}

int32_t
mc_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
		int32_t op_errno, fd_t *fd, object_t *object, struct stat *stbuf)
{
	int32_t    flags = 0;
	mc_file_t  *file = NULL;
	mc_conf_t  *conf = NULL;
	mc_local_t *local = NULL;

	conf = this->private;

	local = frame->local;
	if (local == NULL) {
		op_ret = -1;
		op_errno = EINVAL;
		goto out;
	}

	flags = local->flags;
	//mcflags = local->mcflags;

	if (op_ret != -1) {
		file = mc_file_create (this, fd);
		if (file == NULL) {
			op_ret = -1;
			op_errno = ENOMEM;
			goto out;
		}

		/*
		   If mandatory locking has been enabled on this file,
		   we disable caching on it
		   */
		if ((fd->object->mode & S_ISGID)
				&& !(fd->object->mode & S_IXGRP))
			file->disabled = 1;
		/* If O_DIRECT then, we disable chaching */
		if (((flags & O_DIRECT) == O_DIRECT)
				|| ((flags & O_ACCMODE) == O_RDONLY)
				|| (((flags & O_SYNC) == O_SYNC)
					&& conf->enable_O_SYNC == _gf_true)) {
			file->window_conf = 0;
		}
#if 0
		if (mcflags & GF_OPEN_NOWB) {
			file->disabled = 1;
		}
#endif
		file->disabled = 1;
		LOCK_INIT (&file->lock);
	}

out:
	STACK_UNWIND(frame, op_ret, op_errno, fd, object, stbuf);
	return 0;
}

int32_t
mc_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
		mode_t mode, fd_t *fd)
{
	mc_local_t *local = NULL;
	int32_t     op_errno = EINVAL;

	local = CALLOC (1, sizeof (*local));
	if (local == NULL) {
		op_errno = ENOMEM;
		goto unwind;
	}

	local->flags = flags;
	//local->mcflags = wbflags;
	local->mode = mode;

	frame->local = local;

	STACK_WIND (frame,
			mc_open_cbk,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->open,
			loc, flags, mode, fd);
	return 0;

unwind:
	STACK_UNWIND(frame, -1, op_errno, NULL);
	return 0;
}

/*int32_t
mc_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
		mode_t mode, fd_t *fd)
{

	mc_local_t *local = NULL;
	int32_t	op_errno = EINVAL;
	local = CALLOC (1, sizeof (*local));
	if (local == NULL) {
		op_errno = ENOMEM;
		goto unwind;
	}

	local->flags = flags;
	frame->local = local;

	STACK_WIND (frame,
			mc_create_cbk,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->create,
			loc, flags, mode, fd);
	return 0;
unwind:
	STACK_UNWIND_STRICT (create, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
	return 0;
}*/

int32_t
mc_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, 
		struct stat *postbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, postbuf);
	return 0;
}
int32_t
mc_sync_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
		int32_t op_errno, struct stat *postbuf)
{
	int32_t      unwind_mark = 0;
	mc_local_t   *local = NULL;
	mc_file_t    *file = NULL;
	mc_request_t *request = NULL;
	mc_conf_t *conf = this->private;
	call_frame_t *origin_frame = NULL;
	int          i = 0;
	char	     size[64];
	void         *start;
	uint64_t     size_tosync;
	uint64_t     gen = 0;
	mc_worker_t *worker;

	local = frame->local;
	file = local->file;
	request = local->request;
	unwind_mark = request->unwind_mark;

	gen = file->gen;
    	i = gen % conf->thread_count;
	worker = conf->workers[i];
	LOCK(&worker->mutex);
	{
		/* Ignore the really op_ret */
		conf->cached_size[i] -= local->op_ret;
	}
	UNLOCK(&worker->mutex);

	LOCK(&local->file->lock);
	{
		file->write_size += op_ret;
		size_tosync = file->window_current - file->write_size;
	}
	UNLOCK(&local->file->lock);
	gf_log("xiaow", GF_LOG_TRACE, "sync reqs[%d],%d   %ld %ld %ld",
			i, request->unwind_mark, conf->cached_size[i], file->write_size, size_tosync);
	file->op_ret = op_ret;
	file->op_errno = op_errno;
	sprintf(size, "%llu", size_tosync);
#if 0
	if(size_tosync){
		mc_filelog(file->fd->object->path, size, conf->logmmap_start, 0);
	}
	else{
		mc_filelog(file->fd->object->path, size, conf->logmmap_start, 1);
	}
#endif
	if(request)
		FREE(request);

	mc_file_unref (file);
	iobref_unref(local->iobref);

	origin_frame = local->origin_frame;

	STACK_DESTROY (frame->root);

	if(unwind_mark == 0 && origin_frame)
		STACK_UNWIND(origin_frame, op_ret, op_errno, postbuf);

	return 0;
}

static void *
mc_process_queue (void *data)
{
	mc_worker_t *worker = (mc_worker_t *)data;
	mc_conf_t *conf = worker->wa_conf;
	list_head_t winds;
	mc_request_t *request = NULL;
	mc_request_t *tmp = NULL;
	int i = worker->thread_id;
	int ret;
	uint32_t  count = 0;

	INIT_LIST_HEAD (&winds);

	while (1) {
		LOCK(&worker->mutex);
		{
#ifndef USLEEP
			while (worker->wait_count == 0) {
                                ret = pthread_cond_wait (&worker->cond, &worker->mutex);
				if (ret != 0){
					perror("thread");
					break;
				}
			}
#else
			count = worker->wait_count;
#endif
			list_for_each_entry_safe(request, tmp, &worker->wait_reqs, list) {
				list_del_init (&request->list);
				list_add_tail(&request->list, &winds);
				--worker->wait_count;
			}

		}
		UNLOCK(&worker->mutex);
#ifdef USLEEP		
		if(count == 0) {
			usleep(10000);
			continue;
		}
#endif
		list_for_each_entry_safe (request, tmp, &winds, list) {
			list_del_init (&request->list);

			if(request->stub->fop == GF_FOP_WRITE) {
				//gf_log("debug", GF_LOG_TRACE, "write call resume %x", request);
			}
			//TODO:may have more routine for other ops;
			
			call_resume(request->stub);
		}
	}

        return NULL;
}

mc_request_t *
mc_enqueue (xlator_t *this, mc_file_t *file, call_stub_t *stub)
{
	mc_request_t *request = NULL;
	call_frame_t *frame = NULL;
	mc_local_t   *local = NULL;
	mc_conf_t *conf = this->private;
        struct iovec *vector = NULL;
        int32_t       count = 0;
	int i = 0;
	uint64_t gen = 0;
	mc_worker_t *worker;

	request = CALLOC (1, sizeof (*request));
	if (request == NULL) {
		goto out;
	}

	INIT_LIST_HEAD (&request->list);

	request->stub = stub;
	request->file = file;

	gen = file->gen;
	i = gen % conf->thread_count;
	worker = conf->workers[i];
	//gf_log("xiaow", GF_LOG_NORMAL, "file is %s, gen is %ld, worker is %d\n", file->fd->object->path, gen, i);
	frame = stub->frame;
	local = frame->local;
	if (local) {
		local->request = request;
	}

    if (stub->fop == GF_FOP_WRITE) {
            vector = stub->args.writev.vector;
            count = stub->args.writev.count;
            request->write_size = iov_length (vector, count);
            local->op_ret = request->write_size;

	//gf_log("xiaow710", GF_LOG_NORMAL, "file is %s,off is %ld, want  write %d:%d,crc32 is %lu", file->fd->object->path, stub->args.writev.off, local->op_ret, (char *)vector->iov_base, crc32(vector->iov_base, vector->iov_len, 0));
            LOCK(&local->file->lock);
            {
                    local->file->window_current += request->write_size;
            }
            UNLOCK(&local->file->lock);

    } else 
            local->op_ret = 0;
    //gf_log("mem-cache", GF_LOG_NORMAL, "window_current is %llu", local->file->window_current);
    local->op_errno = 0;
    request->unwind_mark = 0; 

    LOCK(&worker->mutex);
    {
            list_add_tail(&request->list, &worker->wait_reqs);
            worker->wait_count ++;
            conf->cached_size[i] += local->op_ret;

            if(stub->fop == GF_FOP_WRITE && conf->window_size[i] > conf->cached_size[i]) {
                    request->unwind_mark = 1;
            }
            if (conf->window_size[i] <= conf->cached_size[i])
                    gf_log("xiaow", GF_LOG_TRACE, "cached_size overflow, window_size[%d]: %ld, cached_size[%d]: %ld", i, conf->window_size[i], i, conf->cached_size[i]);

            gf_log("xiaow", GF_LOG_TRACE, "enqueue to reqs[%d], wait_count[%d]= %d %d %ld %ld", 
                            i, i, worker->wait_count, request->unwind_mark, conf->window_size[i], conf->cached_size[i]);
            pthread_cond_broadcast (&worker->cond);
    }
    UNLOCK(&worker->mutex);

out:
	return request;
}

#ifndef READV
int32_t
mc_readv_cbk (call_frame_t *frame,
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
int32_t
mc_readv (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd,
	       size_t size,
	       off_t offset)
{
	mc_file_t    *file = NULL;
	uint64_t      tmp_file = 0;
	int32_t       op_ret = -1, op_errno = EINVAL;
	if (fd_ctx_get (fd, this, &tmp_file)) {
		gf_log (this->name, GF_LOG_DEBUG, "write behind file pointer is"
				" not stored in context of fd(%p), returning EBADFD",
				fd);

		op_errno = EBADFD;
		goto unwind;
	}
	file = (mc_file_t *)(long)tmp_file;
	//if(file->disabled)
	if(1)
		STACK_WIND (frame,
				mc_readv_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->readv,
				fd,
				size,
				offset);
	else
		goto unwind;
	return 0;
unwind:

	STACK_UNWIND (frame, op_ret, op_errno, NULL, 0, NULL, NULL);
	return 0;
}
#endif

int32_t
mc_writev_helper (call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
		int32_t count, off_t offset, struct iobref *iobref)
{
	STACK_WIND (frame, mc_sync_cbk,
			FIRST_CHILD (frame->this),
			FIRST_CHILD (frame->this)->fops->writev,
			fd, vector, count, offset, iobref);
	return 0;

}

int32_t
mc_writev (call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
		int32_t count, off_t offset, struct iobref *iobref)
{
	call_frame_t *process_frame = NULL;
	struct stat   buf = {0,};
	mc_file_t    *file = NULL;
	char          mc_disabled = 0;
	uint64_t      tmp_file = 0;
	call_stub_t  *stub = NULL;
	mc_local_t   *local = NULL;
	mc_request_t *request = NULL;
	int32_t       op_ret = -1, op_errno = EINVAL;
	int	      i = 0;
	
	if (fd_ctx_get (fd, this, &tmp_file)) {
		gf_log (this->name, GF_LOG_DEBUG, "write behind file pointer is"
				" not stored in context of fd(%p), returning EBADFD",
				fd);

		op_errno = EBADFD;
		goto unwind;
	}
	gf_log (this->name, GF_LOG_TRACE, "frame %p, offset %ld memcachew  vecotr %p %d iobref %p",
		frame, offset, vector->iov_base, count, iobref);

	file = (mc_file_t *)(long)tmp_file;
	if  (file == NULL) {
		gf_log (this->name, GF_LOG_DEBUG,
				"mc_file not found for fd %p", fd);
		op_errno = EBADFD;
		goto unwind;
	}

	if (file != NULL) {
		LOCK (&file->lock);
		{
			op_ret = file->op_ret;
			op_errno = file->op_errno;

			file->op_ret = 0;
			if(file->disabled)
				mc_disabled = 1;

			if(file->cache_type == 0)
				file->cache_type = 1;
			else if(file->cache_type == 2){
				gf_log (this->name, GF_LOG_ERROR,
						"do write operation in reading file %p", fd);
				op_ret = -1;
				op_errno = EINVAL;
			}
		}
		UNLOCK (&file->lock);
	} else {
		mc_disabled = 1;
	}

	if (op_ret == -1) {
		STACK_UNWIND (frame, op_ret, op_errno,
				NULL, NULL);
		return 0;
	}

	if (mc_disabled) {
		gf_log (this->name, GF_LOG_TRACE, "disable mem-cache for file %p", file);
		STACK_WIND (frame, mc_writev_cbk,
				FIRST_CHILD (frame->this),
				FIRST_CHILD (frame->this)->fops->writev,
				fd, vector, count, offset, iobref);
		return 0;
	}

	process_frame = copy_frame (frame);
	local = CALLOC (1, sizeof (*local));
	if (process_frame == NULL || local == NULL) {
		op_errno = ENOMEM;
		goto unwind;
		return 0;
	}

	process_frame->local = local;
	local->vec_buf = NULL;
	local->file = file;
	local->origin_frame = frame;
	local->iobref = NULL;
	

	stub = fop_writev_stub (process_frame, mc_writev_helper, fd, vector, count, offset,
			iobref);
	if (stub == NULL) {
		op_errno = ENOMEM;
		goto unwind;
	} else {
		local->iobref = iobref_ref(iobref);
	}

	request = mc_enqueue (this, file, stub);
	if (request == NULL) {
		op_errno = ENOMEM;
		goto unwind;
	}

	mc_file_ref(file);

	if(request->unwind_mark) {
		STACK_UNWIND(frame, local->op_ret, local->op_errno, &buf, &buf);
	}

	return 0;

unwind:
	STACK_UNWIND(frame, -1, op_errno, NULL, NULL);

	if (process_frame) {
		STACK_DESTROY (process_frame->root);
	}

	if(local) {
		for(i = 0; i < count; i++) {
			if (local->vec_buf[i] != NULL) {
				FREE(local->vec_buf[i]);
			} else {
				break;
			}
		}

		FREE(local->vec_buf);
		FREE(local);
	}

	if (stub) {
		call_stub_destroy (stub);
	}

	return 0;
}

int32_t
mc_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
		int32_t op_errno,  struct stat *stbuf)
{
	call_frame_t *origin_frame = NULL;
	mc_local_t *local = NULL;
	mc_file_t  *file = NULL;
	mc_conf_t  *conf = NULL;
	mc_request_t *request = NULL;
	char        unwind = 0;
	int         cache_type = 0;

	conf = this->private;
	local = frame->local;

	if ((local != NULL) && (local->file != NULL)) {
		file = local->file;
		request = local->request;
		cache_type = file->cache_type;
		if (file->op_ret == 0) {
			file->op_ret = op_ret;
			file->op_errno = op_errno;
		}
		if(request)
			FREE(request);

		origin_frame = local->origin_frame;
		mc_file_unref(file);

		if (conf->flush_behind && cache_type == 1) {
			unwind = 1;
		}
	}

	if(cache_type == 1) {
		if (!unwind && origin_frame != NULL) 
			STACK_UNWIND (origin_frame, op_ret, op_errno, stbuf);

		STACK_DESTROY(frame->root);
	} else {
		STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	}

	return 0;
}

static int32_t
mc_flush_helper (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	STACK_WIND (frame,
			mc_flush_cbk,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->flush,
			fd);
	return 0;
}
int32_t
mc_flush (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	mc_conf_t    *conf = NULL;
	mc_file_t    *file = NULL;
	mc_local_t   *local = NULL;
	uint64_t      tmp_file = 0;
	call_stub_t  *stub = NULL;
	call_frame_t *process_frame = NULL;
	mc_request_t *request = NULL;
	struct stat   st;
	int32_t       op_errno = 0;
	int           cache_type = 0;
	int           wind_here = 1;

	conf = this->private;
	if (fd_ctx_get (fd, this, &tmp_file)) {
		gf_log (this->name, GF_LOG_DEBUG, "write behind file pointer is"
				" not stored in context of fd(%p), returning EBADFD",
				fd);
		STACK_UNWIND(frame, -1, EBADFD, NULL);
		return 0;
	}

	file = (mc_file_t *)(long)tmp_file;

	if (file != NULL) {

		cache_type = file->cache_type;
		if (cache_type == 1) {

			wind_here = 0;

			process_frame = copy_frame(frame);
			local = CALLOC (1, sizeof (*local));
			if (local == NULL || process_frame == NULL) {
				op_errno = ENOMEM;
				goto unwind;
			}

			local->vec_buf = NULL;
			local->file = file;
			local->origin_frame = frame;
			process_frame->local = local;
			stub = fop_flush_stub (process_frame, mc_flush_helper, fd);
			if (stub == NULL) {
				op_errno = ENOMEM;
				goto unwind;
			}

			request = mc_enqueue (this, file, stub);
			if (request == NULL) {
				op_errno = ENOMEM;
				goto unwind;

			}
			mc_file_ref (file);

			if(conf->flush_behind) {
				/* set stat values from fd->object attrbutes */
				if(fd->object != NULL)
				{
					st.st_mode = fd->object->mode;
					st.st_ino = fd->object->lno;
					st.st_uid = fd->object->uid;
					st.st_gid = fd->object->gid;
					st.st_size = fd->object->size;
					st.st_atime = fd->object->atime;
					st.st_mtime = fd->object->mtime;
					st.st_ctime = fd->object->ctime;
					/* st arguments owned by hadafs */
					st.st_dev = 200;
					st.st_rdev = 200;
					st.st_blksize = 4096;
					st.st_nlink = 0;
					st.st_blocks = st.st_size / 512;
				}
				STACK_UNWIND(frame, 0, 0, &st);

			}
		} else {
			wind_here = 1;
		}
	}


	if (file == NULL || wind_here == 1){
		STACK_WIND (frame,
				mc_flush_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->flush,
				fd);
	}

	return 0;

unwind:
	if(process_frame)
		STACK_DESTROY(process_frame->root);

	if(local)
		FREE(local);

	STACK_UNWIND(frame, -1, op_errno);

	return 0;
}
/**
 *  * mc_ioctl_cbk - 
 *   */
int32_t
mc_ioctl_cbk (call_frame_t *frame, void *cookie,xlator_t *this, int32_t op_ret,
		 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

/**
 *  * mc_ioctl - 
 *   */
int32_t
mc_ioctl (call_frame_t *frame, xlator_t *this, fd_t *fd, uint32_t cmd, 
		uint64_t arg)
{
	xlator_t *child = NULL;
	uint64_t tmp_file = 0;
	mc_file_t *file = NULL;

	if (fd_ctx_get (fd, this, &tmp_file)) {
		gf_log (this->name, GF_LOG_DEBUG, "write behind file pointer is"
				" not stored in context of fd(%p), returning EBADFD",
				fd);
		STACK_UNWIND(frame, -1, EBADFD, NULL);
		return 0;
	}

	file = (mc_file_t *)(long)tmp_file;
	switch (cmd){
	case HADAFS_IOC_SETMC:
		file->disabled = 0;
		STACK_UNWIND (frame, 0, 0);
		break;
	default :
		STACK_WIND (frame, mc_ioctl_cbk, FIRST_CHILD(this), 
			FIRST_CHILD(this)->fops->ioctl, fd, cmd, arg);
		break;
	}

	return 0;
}
static int32_t
mc_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
		int32_t op_errno, struct stat *prebuf, struct stat *postbuf)
{
	call_frame_t *origin_frame = NULL;
	mc_conf_t  *conf = NULL;
	mc_local_t   *local = NULL;
	mc_file_t    *file = NULL;
	mc_request_t *request = NULL;
	int	     cache_type = 0;
	char     unwind = 0;

	conf = this->private;
	local = frame->local;

	if ((local != NULL) && (local->file != NULL)) {
		file = local->file;
		request = local->request;
		origin_frame = local->origin_frame;
		cache_type = file->cache_type;
		if (file->op_ret == 0) {
			file->op_ret = op_ret;
			file->op_errno = op_errno;
		}
		if(request)
			FREE(request);

		mc_file_unref(file);

		if (conf->flush_behind && cache_type == 1) {
			unwind = 1;
		}
	}

	if(cache_type == 1) {
	if (!unwind && origin_frame != NULL) 
		STACK_UNWIND(origin_frame, op_ret, op_errno, prebuf, postbuf);
		STACK_DESTROY(frame->root);
	} else {
		STACK_UNWIND(frame, op_ret, op_errno, prebuf, postbuf);
	}
	return 0;
}


int32_t
mc_release (xlator_t *this, fd_t *fd)
{
	uint64_t   file_ptr = 0;
	mc_file_t *file = NULL;

	if( !fd_ctx_get (fd, this, &file_ptr) )
		file = (mc_file_t *) (long) file_ptr;
	else	
		gf_log (this->name, GF_LOG_ERROR, "write behind file pointer is"
                                " not stored in context of fd(%p), returning EBADFD",fd);

	if (file != NULL) {
		mc_file_destroy (file);
	}

	return 0;
}


int32_t
init (xlator_t *this)
{
	dict_t    *options = NULL;
	mc_conf_t *conf = NULL;
	char      *str = NULL;
	int32_t    ret = -1;
	int       i = 0;
	int32_t   thread_count;

	if ((this->children == NULL)
			|| this->children->next) {
		gf_log (this->name, GF_LOG_ERROR,
				"FATAL: write-behind (%s) not configured with exactly "
				"one child",
				this->name);
		return -1;
	}

	if (this->parents == NULL) {
		gf_log (this->name, GF_LOG_WARNING,
				"dangling volume. check volfile");
	}

	options = this->options;

	conf = CALLOC (1, sizeof (*conf));
	if (conf == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
				"FATAL: Out of memory");
		return -1;
	}

	conf->enable_O_SYNC = _gf_false;
	ret = dict_get_str (options, "enable-O_SYNC",
			&str);
	if (ret == 0) {
		ret = gf_string2boolean (str,
				&conf->enable_O_SYNC);
		if (ret == -1) {
			gf_log (this->name, GF_LOG_ERROR,
					"'enable-O_SYNC' takes only boolean arguments");
			return -1;
		}
	}
	ret = dict_get_int32(options, "thread-count", &thread_count);
	if (ret < 0){
		thread_count = THREAD_COUNT;
	}else{
		if (thread_count < MC_MIN_THREADS) {
                        gf_log ("mem-cache", GF_LOG_WARNING,
                                "Number of threads opted is less then min"
                                "threads allowed scaling it up to min");
                        thread_count = MC_MIN_THREADS;
                }
                if (thread_count > MC_MAX_THREADS) {
                        gf_log ("mem-cache", GF_LOG_WARNING,
                                "Number of threads opted is more then max"
                                " threads allowed scaling it down to max");
                        thread_count = MC_MAX_THREADS;
                }
	}
	conf->thread_count = thread_count;
	/* configure 'option window-size <size>' */
	for(i = 0; i < thread_count; i++){
		conf->window_size[i] = MC_WINDOW_SIZE/thread_count;
		ret = dict_get_str (options, "cache-size",
				&str);
		if (ret == 0) {
			ret = gf_string2bytesize (str,
					&conf->window_size[i]);
			if (ret != 0) {
				gf_log (this->name, GF_LOG_ERROR,
						"invalid number format \"%s\" of \"option "
						"window-size\"",
						str);
				FREE (conf);
				return -1;
			}
			conf->window_size[i] = conf->window_size[i]/thread_count;
		}
	}
	/* configure 'option flush-behind <on/off>' */
	conf->flush_behind = 1;
	ret = dict_get_str (options, "flush-behind",
			&str);
	if (ret == 0) {
		ret = gf_string2boolean (str,
				&conf->flush_behind);
		if (ret == -1) {
			gf_log (this->name, GF_LOG_ERROR,
					"'flush-behind' takes only boolean arguments");
			return -1;
		}

		if (conf->flush_behind) {
			gf_log (this->name, GF_LOG_DEBUG,
					"enabling flush-behind");
		}
	}
	conf->logfile = NULL;
	ret = dict_get_str (options, "log-file",
			&conf->logfile);
	if (ret != 0) {
		gf_log (this->name, GF_LOG_ERROR,
				"option 'log-file' error");
		return -1;
	}
	LOCK_INIT (&conf->lock);
	conf->workers = CALLOC (thread_count, sizeof (mc_worker_t *));
	ret = __mc_workers_scale(conf, conf->workers);
	if(ret == -1) {
		gf_log (this->name, GF_LOG_ERROR,
				"start process request thread failed");
		return -1;
	}
        /* mmap logfile */
	conf->logmmap_start = mc_map(LOG_SIZE, conf->logfile);
	
	this->private = conf;

	return 0;
}


void
fini (xlator_t *this)
{
	mc_conf_t *conf = this->private;
        /* munmap logfile */
	munmap(conf->logmmap_start, LOG_SIZE);

	FREE (conf);
	return;
}


struct xlator_fops fops = {
	.writev      = mc_writev,
	.open        = mc_open,
	.flush       = mc_flush,
	.ioctl       = mc_ioctl,
	.readv       = mc_readv
	//.fsync       = mc_fsync,
	//TODO
	//add read op, change file cache type in read op
	//add fsync op, running as flush
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
	.release  = mc_release
};

/*struct xlator_dumpops dumpops = {
};*/

struct volume_options options[] = {
	{ .key  = {"thread-count"},
	  .type = GF_OPTION_TYPE_INT,
	  .min  = MC_MIN_THREADS,
	  .max  = MC_MAX_THREADS
	},
	{ .key  = {"flush-behind"},
		.type = GF_OPTION_TYPE_BOOL
	},
	{ .key  = {"cache-size", "window-size"},
		.type = GF_OPTION_TYPE_SIZET,
		.min  = 512 * GF_UNIT_KB,
		.max  = 100 * GF_UNIT_GB
	},
	{ .key = {"log-file"},
		.type = GF_OPTION_TYPE_PATH
	},
	{ .key = {"enable-O_SYNC"},
		.type = GF_OPTION_TYPE_BOOL,
	},
	{ .key = {NULL} },
};
