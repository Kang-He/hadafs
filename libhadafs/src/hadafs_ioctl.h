#ifndef _HADAFS_IOCTL_H_
#define _HADAFS_IOCTL_H_

#include <linux/ioctl.h>

/* define HADAFS ioctl cmd */
#define HADAFS_CLIENT_BIT			0x1
#define HADAFS_SERVER_BIT			0x2

#define HADAFS_TYPE			'f'     
#define HADAFS_IOC_DATA_TYPE      	long

/* cmd */
//#define HADAFS_IOC_SETMC			_IOW('f',0x10,long) /* set mem-cache open */
#define HADAFS_IOC_SETMC			1317131 /* set mem-cache open */

typedef unsigned long 	__u64;
typedef unsigned int  	__u32;
typedef unsigned short 	__u16;

#endif

