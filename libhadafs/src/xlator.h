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

#ifndef _XLATOR_H
#define _XLATOR_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>


#include "hadafs.h"
#include "logging.h"
#include "common-utils.h"
#include "dict.h"
#include "compat.h"
#include "list.h"

#define FIRST_CHILD(xl) (xl->children->xlator)

struct _xlator;
typedef struct _xlator xlator_t;
struct _loc;
typedef struct _loc loc_t;


typedef int32_t (*event_notify_fn_t) (xlator_t *this,
				      int32_t event,
				      void *data,
				      ...);

#include "list.h"
#include "stack.h"
#include "iobuf.h"
#include "object.h"
#include "fd.h"

struct _loc {
	const char *path;
	char       *sid;
	uint32_t    soffset;
	object_t    *object;
};


struct xlator_stats {
	uint64_t nr_files;         /* Number of files open via this xlator */
	uint64_t free_disk;        /* Mega bytes */
	uint64_t total_disk_size;  /* Mega Bytes */
	uint64_t disk_usage;       /* Mega bytes */
	uint64_t disk_speed;       /* MHz or Mbps */
	uint64_t nr_clients;       /* Number of client nodes */
	uint64_t write_usage;
	uint64_t read_usage;       /* add more stats here */
};



typedef int32_t (*mop_stats_cbk_t) (call_frame_t *frame,
				    void *cookie,
				    xlator_t *this,
				    int32_t op_ret,
				    int32_t op_errno,
				    struct xlator_stats *stats);

typedef int32_t (*mop_getspec_cbk_t) (call_frame_t *frame,
				      void *cookie,
				      xlator_t *this,
				      int32_t op_ret,
				      int32_t op_errno,
				      char *spec_data);

typedef int32_t (*fop_checksum_cbk_t) (call_frame_t *frame,
				       void *cookie,
				       xlator_t *this,
				       int32_t op_ret,
				       int32_t op_errno,
				       uint8_t *file_checksum);

typedef int32_t (*mop_setvolume_t) (call_frame_t *frame,
				    xlator_t *this,
				    const char *volume);

typedef int32_t (*mop_stats_t) (call_frame_t *frame,
				xlator_t *this,
				int32_t flags);

typedef int32_t (*mop_getspec_t) (call_frame_t *frame,
				  xlator_t *this,
				  const char *key,
				  int32_t flag);

typedef int32_t (*fop_checksum_t) (call_frame_t *frame,
				   xlator_t *this,
				   loc_t *loc,
				   int32_t flag);

struct xlator_mops {
	mop_stats_t            stats;
	mop_getspec_t          getspec;

	mop_stats_cbk_t        stats_cbk;
	mop_getspec_cbk_t      getspec_cbk;
};

typedef int32_t (*fop_ioctl_cbk_t) (call_frame_t *frame,
				void *cookie,
				xlator_t *this,
				int32_t op_ret,
				int32_t op_errno);

typedef int32_t (*fop_stat_cbk_t) (call_frame_t *frame,
				   void *cookie,
				   xlator_t *this,
				   int32_t op_ret,
				   int32_t op_errno,
				   struct stat *buf);

typedef int32_t (*fop_fstat_cbk_t) (call_frame_t *frame,
				    void *cookie,
				    xlator_t *this,
				    int32_t op_ret,
				    int32_t op_errno,
				    struct stat *buf);

typedef int32_t (*fop_fstat_t) (call_frame_t *frame,
				xlator_t *this,
				fd_t *fd);

typedef int32_t (*fop_open_cbk_t) (call_frame_t *frame,
				     void *cookie,
				     xlator_t *this,
				     int32_t op_ret,
				     int32_t op_errno,
				     fd_t *fd,
				     object_t *object,
				     struct stat *buf);

typedef int32_t (*fop_readv_cbk_t) (call_frame_t *frame,
				    void *cookie,
				    xlator_t *this,
				    int32_t op_ret,
				    int32_t op_errno,
				    struct iovec *vector,
				    int32_t count,
                                    struct iobref *iobref);

typedef int32_t (*fop_writev_cbk_t) (call_frame_t *frame,
				     void *cookie,
				     xlator_t *this,
				     int32_t op_ret,
				     int32_t op_errno,
				     struct stat *buf);

typedef int32_t (*fop_flush_cbk_t) (call_frame_t *frame,
				    void *cookie,
				    xlator_t *this,
				    int32_t op_ret,
				    int32_t op_errno);

typedef int32_t (*fop_unlink_cbk_t) (call_frame_t *frame,
				     void *cookie,
				     xlator_t *this,
				     int32_t op_ret,
				     int32_t op_errno);

typedef int32_t (*fop_unlink_t) (call_frame_t *frame,
				 xlator_t *this,
				 loc_t *loc);

typedef int32_t (*fop_stat_t) (call_frame_t *frame,
			       xlator_t *this,
			       loc_t *loc);

typedef int32_t (*fop_open_t) (call_frame_t *frame,
				 xlator_t *this,
				 loc_t *loc,
				 int32_t flags,
				 mode_t mode,
				 fd_t *fd);

typedef int32_t (*fop_readv_t) (call_frame_t *frame,
				xlator_t *this,
				fd_t *fd,
				size_t size,
				off_t offset);

typedef int32_t (*fop_writev_t) (call_frame_t *frame,
				 xlator_t *this,
				 fd_t *fd,
				 struct iovec *vector,
				 int32_t count,
				 off_t offset,
                                 struct iobref *iobref);

typedef int32_t (*fop_flush_t) (call_frame_t *frame,
				xlator_t *this,
				fd_t *fd);


typedef int32_t (*fop_ioctl_t) (call_frame_t *frame,
				xlator_t *this,
				fd_t *fd,
				uint32_t cmd, uint64_t arg);

typedef int32_t (*fop_truncate_t) (call_frame_t *frame,
				   xlator_t *this,
				   loc_t *loc,
				   off_t offset);

typedef int32_t (*fop_ftruncate_t) (call_frame_t *frame,
				    xlator_t *this,
				    fd_t *fd,
				    off_t offset);

typedef int32_t (*fop_truncate_cbk_t) (call_frame_t *frame,
				       void *cookie,
				       xlator_t *this,
				       int32_t op_ret,
				       int32_t op_errno,
                       struct stat *postbuf);

typedef int32_t (*fop_ftruncate_cbk_t) (call_frame_t *frame,
					void *cookie,
					xlator_t *this,
					int32_t op_ret,
					int32_t op_errno,
                    struct stat *postbuf);

struct xlator_fops {
	fop_unlink_t         unlink;
	fop_stat_t	     stat;
	fop_fstat_t	     fstat;
	fop_open_t           open;
	fop_readv_t          readv;
	fop_writev_t         writev;
	fop_flush_t          flush;
	fop_ioctl_t 	     ioctl;
	fop_checksum_t       checksum;
    fop_truncate_t       truncate;
	fop_ftruncate_t      ftruncate;
	/* these entries are used for a typechecking hack in STACK_WIND _only_ */
	fop_unlink_cbk_t         unlink_cbk;
	fop_stat_cbk_t		 stat_cbk;
	fop_fstat_cbk_t		 fstat_cbk;
	fop_open_cbk_t           open_cbk;
	fop_readv_cbk_t          readv_cbk;
	fop_writev_cbk_t         writev_cbk;
	fop_flush_cbk_t          flush_cbk;
	fop_ioctl_cbk_t         ioctl_cbk;
	fop_checksum_cbk_t       checksum_cbk;
	fop_truncate_cbk_t       truncate_cbk;
    fop_ftruncate_cbk_t      ftruncate_cbk;
};

typedef int32_t (*cbk_forget_t) (xlator_t *this,
				 object_t *object);

typedef int32_t (*cbk_release_t) (xlator_t *this,
				  fd_t *fd);

struct xlator_cbks {
	cbk_forget_t    forget;
	cbk_release_t   release;
};

typedef struct xlator_list {
	xlator_t           *xlator;
	struct xlator_list *next;
} xlator_list_t;

/* Add possible new type of option you may need */
typedef enum {
  	GF_OPTION_TYPE_ANY = 0,
  	GF_OPTION_TYPE_STR,
  	GF_OPTION_TYPE_INT,
  	GF_OPTION_TYPE_SIZET,
  	GF_OPTION_TYPE_PERCENT,
  	GF_OPTION_TYPE_BOOL,
  	GF_OPTION_TYPE_XLATOR,
  	GF_OPTION_TYPE_PATH,
  	GF_OPTION_TYPE_TIME,
	GF_OPTION_TYPE_DOUBLE,
        GF_OPTION_TYPE_INTERNET_ADDRESS,
} volume_option_type_t;

#define ZR_VOLUME_MAX_NUM_KEY    4
#define ZR_OPTION_MAX_ARRAY_SIZE 64

/* Each translator should define this structure */
typedef struct volume_options {
  	char                *key[ZR_VOLUME_MAX_NUM_KEY]; 
	                           /* different key, same meaning */
  	volume_option_type_t type;       
  	int64_t              min;  /* -1 means no range */
  	int64_t              max;  /* -1 means no range */
  	char                *value[ZR_OPTION_MAX_ARRAY_SIZE];  
                                   /* If specified, will check for one of 
				      the value from this array */
	char                *description; /* about the key */
} volume_option_t;

typedef struct vol_opt_list {
	struct list_head  list;
	volume_option_t  *given_opt;
} volume_opt_list_t;

struct _xlator {
	/* Built during parsing */
	char          *name;
	char          *type;
	xlator_t      *next;
	xlator_t      *prev;
	xlator_list_t *parents;
	xlator_list_t *children;
	dict_t        *options;
	
	/* Set after doing dlopen() */
	struct xlator_fops *fops;
	struct xlator_mops *mops;
	struct xlator_cbks *cbks;
	struct list_head   volume_options;  /* list of volume_option_t */

	void              (*fini) (xlator_t *this);
	int32_t           (*init) (xlator_t *this);
	event_notify_fn_t notify;

	/* Misc */
	hadafs_ctx_t  *ctx;
	object_table_t    *otable;
	char              ready;
	char              init_succeeded;
	void             *private;
};

int validate_xlator_volume_options (xlator_t *xl, volume_option_t *opt);

int32_t xlator_set_type (xlator_t *xl, const char *type);

xlator_t *file_to_xlator_tree (hadafs_ctx_t *ctx,
			       FILE *fp);


int32_t xlator_tree_init (xlator_t *xl);
int32_t xlator_tree_free (xlator_t *xl);

void xlator_tree_fini (xlator_t *xl);

void xlator_foreach (xlator_t *this,
		     void (*fn) (xlator_t *each,
				 void *data),
		     void *data);

xlator_t *xlator_search_by_name (xlator_t *any, const char *name);
int loc_copy (loc_t *dst, loc_t *src);
#define loc_dup(src, dst) loc_copy(dst, src)
void loc_wipe (loc_t *loc);

#define GF_STAT_PRINT_FMT_STR "%"PRIx64",%"PRIx64",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx64",%"PRIx64",%"PRIx32",%"PRIx64",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32"\n"

#define GF_STAT_SCAN_FMT_STR "%"SCNx64",%"SCNx64",%"SCNx32",%"SCNx32",%"SCNx32",%"SCNx32",%"SCNx64",%"SCNx64",%"SCNx32",%"SCNx64",%"SCNx32",%"SCNx32",%"SCNx32",%"SCNx32",%"SCNx32",%"SCNx32"\n"

#define GF_STATFS_PRINT_FMT_STR "%"PRIx32",%"PRIx32",%"PRIx64",%"PRIx64",%"PRIx64",%"PRIx64",%"PRIx64",%"PRIx64",%"PRIx32",%"PRIx32",%"PRIx32"\n"

#define GF_STATFS_SCAN_FMT_STR "%"SCNx32",%"SCNx32",%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx32",%"SCNx32",%"SCNx32"\n"

#endif /* _XLATOR_H */

