#ifndef _SWNET_HEADER_H_
#define _SWNET_HEADER_H_
struct _swnet_verbs_header {
        char     colonO[3];
        uint32_t size1;
        uint32_t size2;

        unsigned int local_qpn, remote_qpn;     // used to store qp number when lookup peer

        unsigned long post_to_free;     // last post need to be freed
        unsigned long current_post;     // RDMA post
	unsigned long rdma_free;     // last rdma addr to be freed by remote

#ifndef WEIWEI_20180205
        unsigned long sendid;
#endif
#ifndef WEIWEI_20180302
        uint32_t cksum;
#endif

        unsigned long datacopy;
        char     version;
} __attribute__((packed));
typedef struct _swnet_verbs_header swnet_verbs_header_t;
#endif /*_SWNET_HEADER_H_*/
