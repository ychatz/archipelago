#ifndef _XSEG_H
#define _XSEG_H

#ifndef XSEG_VERSION
#define XSEG_VERSION 2012022601
#endif

#ifndef XSEG_PAGE_SHIFT
#define XSEG_PAGE_SHIFT 12
#endif

#define XSEG_BASE (0x37fd0UL << XSEG_PAGE_SHIFT)
#define XSEG_BASE_AS_PTR ((void *)XSEG_BASE)
#define XSEG_BASE_AS_BUF ((char *)XSEG_BASE)
#define XSEG_OFFSET(base, ptr) ((unsigned long)(ptr) - (unsigned long)(base))
#define XSEG_PTR_CONVERT(ptr, src, dst) ((void *)((unsigned long)(dst) + XSEG_OFFSET(src, ptr)))
#define XSEG_TAKE_PTR(ptr, base) XSEG_PTR_CONVERT(ptr, XSEG_BASE, base)
#define XSEG_MAKE_PTR(ptr, base) XSEG_PTR_CONVERT(ptr, base, XSEG_BASE)

#include <sys/util.h>
#include <xtypes/xq.h>
#include <xtypes/xobj.h>
#include <xtypes/xhash.h>
#include <xtypes/xpool.h>

typedef uint64_t xserial;
typedef uint32_t xport;

#define NoSerial ((xserial)-1)
#define NoPort ((xport) -1)

#ifndef XSEG_DEF_REQS
#define XSEG_DEF_REQS 256
#endif

#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 32
#endif

#ifndef MAX_WAITERS
#define MAX_WAITERS 32
#endif

/* Peers and Segments
 *
 *  Segments are memory segments shared among peers.
 *  Peers are local execution contexes that share a segment.
 *
 *  xseg_type and xseg_peer
 *
 *  A peer needs an xseg_type in order to
 *  create or access a certain segment type,
 *  and it needs an xseg_peer in order to
 *  communicate with a certain type of peer.
 *  Both segment and peer types are identified by name strings.
 *
 *  Note that each peer (that is, context) type will need
 *  different code to access the same type of segment or peer.
 *  Therefore each peer must have its own "customized" version
 *  of the xseg library.
 *
 *  This is accomplished by mechanisms for registering both
 *  xseg_type's and xseg_peer's. This can be done at both at build time
 *  and at runtime, through a plugin-loading mechanism (where applicable).
 *  The plugin namespace serves both segment and peer type namespace,
 *  so if a segment type has the same name with a peer type,
 *  they must be provided by the same plugin.
 *
 *  Note also that peers of different types may share the same segment.
 *  Therefore each peer must know the type of each peer it needs to
 *  communicate with, and have a driver for it.
 *
*/

struct xseg;
struct xseg_port;

#define MAGIC_OBJH 	1
#define MAGIC_REQ 	2
#define MAGIC_PORT 	3

struct xseg_operations {
	void  (*mfree)(void *mem);
	long  (*allocate)(const char *name, uint64_t size);
	long  (*deallocate)(const char *name);
	void *(*map)(const char *name, uint64_t size, struct xseg *seg);
	void  (*unmap)(void *xseg, uint64_t size);
};

#define XSEG_NAMESIZE 256
#define XSEG_TNAMESIZE 32

struct xseg_type {
	struct xseg_operations ops;
	char name[XSEG_TNAMESIZE];
};

struct xseg_peer_operations {
	int   (*local_signal_init)(void);
	void  (*local_signal_quit)(void);
	int   (*remote_signal_init)(void);
	void  (*remote_signal_quit)(void);
	int   (*signal_join)(struct xseg *xseg);
	int   (*signal_leave)(struct xseg *xseg);
	int   (*prepare_wait)(struct xseg *xseg, uint32_t portno);
	int   (*cancel_wait)(struct xseg *xseg, uint32_t portno);
	int   (*wait_signal)(struct xseg *xseg, uint32_t usec_timeout);
	int   (*signal)(struct xseg *xseg, uint32_t portno);
	void *(*malloc)(uint64_t size);
	void *(*realloc)(void *mem, uint64_t size);
	void  (*mfree)(void *mem);
};

struct xseg_peer {
	struct xseg_peer_operations peer_ops;
	char name[XSEG_TNAMESIZE];
};

struct xseg_config {
	uint64_t heap_size;	/* heap size in MB */
	uint32_t nr_ports;
	uint32_t page_shift;	/* the alignment unit */
	char type[XSEG_TNAMESIZE]; /* zero-terminated identifier */
	char name[XSEG_NAMESIZE];  /* zero-terminated identifier */
};

struct xseg_port {
	struct xlock fq_lock;
	struct xlock rq_lock;
	struct xlock pq_lock;
	xptr free_queue;
	xptr request_queue;
	xptr reply_queue;
	uint64_t owner;
	uint64_t peer_type;
	uint32_t portno;
	uint64_t max_alloc_reqs;
	uint64_t alloc_reqs;
	struct xlock port_lock;
	volatile uint64_t waitcue;
	struct xpool waiters;
	struct xpool_node bufs[MAX_WAITERS];
};

struct xseg_request;

struct xseg_task {
	uint64_t epoch;
	struct xseg_request *req;
	xqindex *deps;
	xqindex nr_deps;
	xqindex __alloced_deps;
};

/* OPS */
#define X_PING      0
#define X_READ      1
#define X_WRITE     2
#define X_SYNC      3
#define X_TRUNCATE  4
#define X_DELETE    5
#define X_ACQUIRE   6
#define X_RELEASE   7
#define X_COPY      8
#define X_CLONE     9
#define X_COMMIT   10
#define X_INFO     11
#define X_MAPR     12
#define X_MAPW     13
#define X_OPEN     14
#define X_CLOSE    15

/* FLAGS */
#define XF_NOSYNC (1 << 0)
#define XF_FLUSH  (1 << 1)
#define XF_FUA    (1 << 2)

/* STATES */
#define XS_SERVED	(1 << 0)
#define XS_FAILED	(1 << 1)

#define XS_ACCEPTED	(1 << 2)
#define XS_PENDING	(2 << 2)
#define XS_SERVING	(3 << 2)
#define XS_CONCLUDED	(3 << 2)

struct xseg_request {
	xserial serial;
	uint64_t offset;
	uint64_t size; /* FIXME: why are there both size and datalen fields? */
		/* FIXME: why does filed use ->datalen instead of ->size? */
	uint64_t serviced;
	xptr data;
	uint64_t datalen;
	xptr target;
	uint32_t targetlen;
	uint32_t op;
	uint32_t state;
	uint32_t flags;
	xport src_portno;
	xport src_transit_portno;
	xport dst_portno;
	xport dst_transit_portno;
	struct xq path;
	xqindex path_bufs[MAX_PATH_LEN];
	/* pad */
	xptr buffer;
	uint64_t bufferlen;
	xqindex task;
	uint64_t priv;
	struct timeval timestamp;
	uint64_t elapsed;
};

struct xseg_shared {
	uint64_t flags;
	char (*peer_types)[XSEG_TNAMESIZE]; /* alignment? */
	uint32_t nr_peer_types;
};

struct xseg_private {
	struct xseg_type segment_type;
	struct xseg_peer peer_type;
	struct xseg_peer **peer_types;
	uint32_t max_peer_types;
	void (*wakeup)(uint32_t portno);
	xhash_t *req_data;
	struct xlock reqdatalock;
};

struct xseg_counters {
	uint64_t avg_req_lat;
	uint64_t req_cnt;
};

struct xseg {
	uint64_t version;
	uint64_t segment_size;
	struct xseg *segment;
	struct xheap *heap;
	struct xobject_h *object_handlers;

	struct xobject_h *request_h;
	struct xobject_h *port_h;
	xptr *ports;
	xport *src_gw, *dst_gw;

	struct xseg_shared *shared;
	struct xseg_private *priv;
	uint32_t max_peer_types;
	struct xseg_config config;
	struct xseg_counters counters;
};

#define XSEG_F_LOCK 0x1

/* ================= XSEG REQUEST INTERFACE ================================= */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_initialize      ( void                            );

                int    xseg_finalize        ( void                            );

                int    xseg_parse_spec      ( char                * spec,
                                              struct xseg_config  * config    );

   struct xseg_port *  xseg_bind_port       ( struct xseg         * xseg,
                                              uint32_t              portno    );

    static uint32_t    xseg_portno          ( struct xseg         * xseg,
                                              struct xseg_port    * port      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_register_type   ( struct xseg_type    * type      );
                int    xseg_unregister_type ( const char          * name      );

                int    xseg_register_peer   ( struct xseg_peer    * peer      );
                int    xseg_unregister_peer ( const char          * name      );

               void    xseg_report_peer_types( void );

            int64_t    xseg_enable_driver   ( struct xseg         * xseg,
                                              const char          * name      );
                int    xseg_disable_driver  ( struct xseg         * xseg,
                                              const char          * name      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_create          ( struct xseg_config  * cfg       );

               void    xseg_destroy         ( struct xseg         * xseg      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
        struct xseg *  xseg_join            ( char                * segtype,
                                              char                * segname,
                                              char                * peertype,
                                              void               (* wakeup    )
                                             (uint32_t              portno   ));

               void    xseg_leave           ( struct xseg         * xseg      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_alloc_requests  ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              uint32_t              nr        );

                int    xseg_free_requests   ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              int                   nr        );

struct xseg_request *  xseg_get_request     ( struct xseg         * xseg,
                                              xport                 src_portno,
					      xport                 dst_portno,
					      uint32_t              flags     );

                int    xseg_put_request     ( struct xseg         * xseg,
                                              struct xseg_request * xreq,
                                              xport                 portno    );

                int    xseg_prep_request    ( struct xseg	  * xseg,
					      struct xseg_request * xreq,
                                              uint32_t              targetlen,
                                              uint64_t              datalen  );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
              xport    xseg_submit          ( struct xseg         * xseg,
                                              struct xseg_request * xreq,      
                                              xport                 portno,
					      uint32_t              flags     );

struct xseg_request *  xseg_receive         ( struct xseg         * xseg,
                                              xport                 portno    );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */

struct xseg_request *  xseg_accept          ( struct xseg         * xseg,
                                              xport                 portno    );

              xport    xseg_respond         ( struct xseg         * xseg,
                                              struct xseg_request * xreq,
                                              xport                 portno,
                                              uint32_t              flags     );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_prepare_wait    ( struct xseg         * xseg,
                                              uint32_t              portno    );

                int    xseg_cancel_wait     ( struct xseg         * xseg,
                                              uint32_t              portno    );

                int    xseg_wait_signal     ( struct xseg         * xseg,
                                              uint32_t              utimeout  );

                int    xseg_signal          ( struct xseg         * xseg,
                                              uint32_t              portno    );
/*                    \___________________/                       \_________/ */



/*                                                                            */
/* ================= XSEG REQUEST INTERFACE ================================= */

struct xseg_port* xseg_get_port(struct xseg *xseg, uint32_t portno);

static inline uint32_t xseg_portno(struct xseg *xseg, struct xseg_port *port)
{
	return port->portno;
}

static inline char* xseg_get_target(struct xseg* xseg, struct xseg_request *req)
{
	return (char *) XPTR_TAKE(req->target, xseg->segment);
}

static inline char* xseg_get_data(struct xseg* xseg, struct xseg_request *req)
{
	return (char *) XPTR_TAKE(req->data, xseg->segment);
}

#define xseg_get_queue(__xseg, __port, __queue) \
	((struct xq *) XPTR_TAKE(__port->__queue, __xseg->segment))

#endif

xport xseg_set_srcgw		(struct xseg *xseg, xport portno, xport srcgw);
xport xseg_getandset_srcgw	(struct xseg *xseg, xport portno, xport srcgw);
xport xseg_set_dstgw		(struct xseg *xseg, xport portno, xport dstgw);
xport xseg_getandset_dstgw	(struct xseg *xseg, xport portno, xport dstgw);

int xseg_set_req_data (struct xseg *xseg, struct xseg_request *xreq, void *data);
int xseg_get_req_data (struct xseg *xseg, struct xseg_request *xreq, void **data);

int xseg_init_local_signal(struct xseg *xseg, xport portno);
void xseg_quit_local_signal(struct xseg *xseg, xport portno);

int xseg_resize_request (struct xseg *xseg, struct xseg_request *req,
			uint32_t new_targetlen, uint64_t new_datalen);

