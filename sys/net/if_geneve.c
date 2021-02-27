/*-
 * Copyright (c) 2014, Bryan Venteicher <bryanv@FreeBSD.org>
 * Copyright (c) 2020, Chelsio Communications.
 * Copyright (c) 2021, Lichao Mu <mulichao@outlook.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/hash.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/refcount.h>
#include <sys/rmlock.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_geneve.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/route/nhop.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/in_fib.h>
#include <netinet6/in6_fib.h>

#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>

#include <machine/in_cksum.h>

struct geneve_softc;
LIST_HEAD(geneve_softc_head, geneve_softc);

struct sx geneve_sx;
SX_SYSINIT(geneve, &geneve_sx, "GENEVE global start/stop lock");

struct geneve_socket_mc_info {
	union geneve_sockaddr		 gnvsomc_saddr;
	union geneve_sockaddr		 gnvsomc_gaddr;
	int				 gnvsomc_ifidx;
	int				 gnvsomc_users;
};

/*
 * The maximum MTU of encapsulated ethernet frame within IPv4/UDP packet.
 */
#define GENEVE_MAX_MTU	(IP_MAXPACKET - \
		60 /* Maximum IPv4 header len */ - \
		sizeof(struct udphdr) - \
		sizeof(struct geneve_header) - \
		ETHER_HDR_LEN - ETHER_CRC_LEN - ETHER_VLAN_ENCAP_LEN)
#define GENEVE_BASIC_IFCAPS (IFCAP_LINKSTATE | IFCAP_JUMBO_MTU)

#define GENEVE_SO_MC_MAX_GROUPS		32

#define GENEVE_SO_VNI_HASH_SHIFT		6
#define GENEVE_SO_VNI_HASH_SIZE		(1 << GENEVE_SO_VNI_HASH_SHIFT)
#define GENEVE_SO_VNI_HASH(_vni, _aws_eni_id)		((_vni + _aws_eni_id) % GENEVE_SO_VNI_HASH_SIZE)

struct geneve_socket {
	struct socket			*gnvso_sock;
	struct rmlock			 gnvso_lock;
	u_int				 gnvso_refcnt;
	union geneve_sockaddr		 gnvso_laddr;
	LIST_ENTRY(geneve_socket)	 gnvso_entry;
	struct geneve_softc_head		 gnvso_vni_hash[GENEVE_SO_VNI_HASH_SIZE];
	struct geneve_socket_mc_info	 gnvso_mc[GENEVE_SO_MC_MAX_GROUPS];
};

#define GENEVE_SO_RLOCK(_vso, _p)	rm_rlock(&(_vso)->gnvso_lock, (_p))
#define GENEVE_SO_RUNLOCK(_vso, _p)	rm_runlock(&(_vso)->gnvso_lock, (_p))
#define GENEVE_SO_WLOCK(_vso)		rm_wlock(&(_vso)->gnvso_lock)
#define GENEVE_SO_WUNLOCK(_vso)		rm_wunlock(&(_vso)->gnvso_lock)
#define GENEVE_SO_LOCK_ASSERT(_vso) \
    rm_assert(&(_vso)->gnvso_lock, RA_LOCKED)
#define GENEVE_SO_LOCK_WASSERT(_vso) \
    rm_assert(&(_vso)->gnvso_lock, RA_WLOCKED)

#define GENEVE_SO_ACQUIRE(_vso)		refcount_acquire(&(_vso)->gnvso_refcnt)
#define GENEVE_SO_RELEASE(_vso)		refcount_release(&(_vso)->gnvso_refcnt)

struct geneve_ftable_entry {
	LIST_ENTRY(geneve_ftable_entry)	 gnvfe_hash;
	uint16_t			 gnvfe_flags;
	uint8_t				 gnvfe_mac[ETHER_ADDR_LEN];
	union geneve_sockaddr		 gnvfe_raddr;
	time_t				 gnvfe_expire;
};

#define GENEVE_FE_FLAG_DYNAMIC		0x01
#define GENEVE_FE_FLAG_STATIC		0x02

#define GENEVE_FE_IS_DYNAMIC(_fe) \
    ((_fe)->gnvfe_flags & GENEVE_FE_FLAG_DYNAMIC)

#define GENEVE_SC_FTABLE_SHIFT		9
#define GENEVE_SC_FTABLE_SIZE		(1 << GENEVE_SC_FTABLE_SHIFT)
#define GENEVE_SC_FTABLE_MASK		(GENEVE_SC_FTABLE_SIZE - 1)
#define GENEVE_SC_FTABLE_HASH(_sc, _mac)	\
    (geneve_mac_hash(_sc, _mac) % GENEVE_SC_FTABLE_SIZE)

LIST_HEAD(geneve_ftable_head, geneve_ftable_entry);

struct geneve_statistics {
	uint32_t	ftable_nospace;
	uint32_t	ftable_lock_upgrade_failed;
	counter_u64_t	txcsum;
	counter_u64_t	tso;
	counter_u64_t	rxcsum;
};

struct geneve_softc {
	struct ifnet			*gnv_ifp;
	int				 gnv_reqcap;
	struct geneve_socket		*gnv_sock;
	uint32_t			 gnv_vni;
	union geneve_sockaddr		 gnv_src_addr;
	union geneve_sockaddr		 gnv_dst_addr;
	uint32_t			 gnv_flags;
#define GENEVE_FLAG_INIT	0x0001
#define GENEVE_FLAG_TEARDOWN	0x0002
#define GENEVE_FLAG_LEARN	0x0004
#define GENEVE_FLAG_ETHER	0x0008

	uint32_t			 gnv_port_hash_key;
	uint16_t			 gnv_min_port;
	uint16_t			 gnv_max_port;
	uint8_t				 gnv_ttl;
	uint64_t			 gnv_aws_eni_id;

	/* Lookup table from MAC address to forwarding entry. */
	uint32_t			 gnv_ftable_cnt;
	uint32_t			 gnv_ftable_max;
	uint32_t			 gnv_ftable_timeout;
	uint32_t			 gnv_ftable_hash_key;
	struct geneve_ftable_head	*gnv_ftable;

	/* Derived from gnv_dst_addr. */
	struct geneve_ftable_entry	 gnv_default_fe;

	struct ip_moptions		*gnv_im4o;
	struct ip6_moptions		*gnv_im6o;

	struct rmlock			 gnv_lock;
	volatile u_int			 gnv_refcnt;

	int				 gnv_unit;
	int				 gnv_vso_mc_index;
	struct geneve_statistics		 gnv_stats;
	struct sysctl_oid		*gnv_sysctl_node;
	struct sysctl_ctx_list		 gnv_sysctl_ctx;
	struct callout			 gnv_callout;
	struct ether_addr		 gnv_hwaddr;
	int				 gnv_mc_ifindex;
	struct ifnet			*gnv_mc_ifp;
	struct ifmedia 			 gnv_media;
	char				 gnv_mc_ifname[IFNAMSIZ];
	LIST_ENTRY(geneve_softc)		 gnv_entry;
	LIST_ENTRY(geneve_softc)		 gnv_ifdetach_list;

	/* For rate limiting errors on the tx fast path. */
	struct timeval err_time;
	int err_pps;
};

#define GENEVE_RLOCK(_sc, _p)	rm_rlock(&(_sc)->gnv_lock, (_p))
#define GENEVE_RUNLOCK(_sc, _p)	rm_runlock(&(_sc)->gnv_lock, (_p))
#define GENEVE_WLOCK(_sc)	rm_wlock(&(_sc)->gnv_lock)
#define GENEVE_WUNLOCK(_sc)	rm_wunlock(&(_sc)->gnv_lock)
#define GENEVE_LOCK_WOWNED(_sc)	rm_wowned(&(_sc)->gnv_lock)
#define GENEVE_LOCK_ASSERT(_sc)	rm_assert(&(_sc)->gnv_lock, RA_LOCKED)
#define GENEVE_LOCK_WASSERT(_sc) rm_assert(&(_sc)->gnv_lock, RA_WLOCKED)
#define GENEVE_UNLOCK(_sc, _p) do {		\
    if (GENEVE_LOCK_WOWNED(_sc))			\
	GENEVE_WUNLOCK(_sc);			\
    else					\
	GENEVE_RUNLOCK(_sc, _p);			\
} while (0)

#define GENEVE_ACQUIRE(_sc)	refcount_acquire(&(_sc)->gnv_refcnt)
#define GENEVE_RELEASE(_sc)	refcount_release(&(_sc)->gnv_refcnt)

#define	satoconstsin(sa)	((const struct sockaddr_in *)(sa))
#define	satoconstsin6(sa)	((const struct sockaddr_in6 *)(sa))

struct geneveudphdr {
	struct udphdr		gnvh_udp;
	struct geneve_header	gnvh_hdr;
} __packed;

struct geneve_opthdr {
	uint16_t	gnvo_class;
	uint8_t		gnvo_type;
	uint8_t		gnvo_length;
} __packed;

static int	geneve_ftable_addr_cmp(const uint8_t *, const uint8_t *);
static void	geneve_ftable_init(struct geneve_softc *);
static void	geneve_ftable_fini(struct geneve_softc *);
static void	geneve_ftable_flush(struct geneve_softc *, int);
static void	geneve_ftable_expire(struct geneve_softc *);
static int	geneve_ftable_update_locked(struct geneve_softc *,
		    const union geneve_sockaddr *, const uint8_t *,
		    struct rm_priotracker *);
static int	geneve_ftable_learn(struct geneve_softc *,
		    const struct sockaddr *, const uint8_t *);
static int	geneve_ftable_sysctl_dump(SYSCTL_HANDLER_ARGS);

static struct geneve_ftable_entry *
		geneve_ftable_entry_alloc(void);
static void	geneve_ftable_entry_free(struct geneve_ftable_entry *);
static void	geneve_ftable_entry_init(struct geneve_softc *,
		    struct geneve_ftable_entry *, const uint8_t *,
		    const struct sockaddr *, uint32_t);
static void	geneve_ftable_entry_destroy(struct geneve_softc *,
		    struct geneve_ftable_entry *);
static int	geneve_ftable_entry_insert(struct geneve_softc *,
		    struct geneve_ftable_entry *);
static struct geneve_ftable_entry *
		geneve_ftable_entry_lookup(struct geneve_softc *,
		    const uint8_t *);
static void	geneve_ftable_entry_dump(struct geneve_ftable_entry *,
		    struct sbuf *);

static struct geneve_socket *
		geneve_socket_alloc(const union geneve_sockaddr *);
static void	geneve_socket_destroy(struct geneve_socket *);
static void	geneve_socket_release(struct geneve_socket *);
static struct geneve_socket *
		geneve_socket_lookup(union geneve_sockaddr *gnvsa);
static void	geneve_socket_insert(struct geneve_socket *);
static int	geneve_socket_init(struct geneve_socket *, struct ifnet *);
static int	geneve_socket_bind(struct geneve_socket *, struct ifnet *);
static int	geneve_socket_create(struct ifnet *, int,
		    const union geneve_sockaddr *, struct geneve_socket **);
static void	geneve_socket_ifdetach(struct geneve_socket *,
		    struct ifnet *, struct geneve_softc_head *);

static struct geneve_socket *
		geneve_socket_mc_lookup(const union geneve_sockaddr *);
static int	geneve_sockaddr_mc_info_match(
		    const struct geneve_socket_mc_info *,
		    const union geneve_sockaddr *,
		    const union geneve_sockaddr *, int);
static int	geneve_socket_mc_join_group(struct geneve_socket *,
		    const union geneve_sockaddr *, const union geneve_sockaddr *,
		    int *, union geneve_sockaddr *);
static int	geneve_socket_mc_leave_group(struct geneve_socket *,
		    const union geneve_sockaddr *,
		    const union geneve_sockaddr *, int);
static int	geneve_socket_mc_add_group(struct geneve_socket *,
		    const union geneve_sockaddr *, const union geneve_sockaddr *,
		    int, int *);
static void	geneve_socket_mc_release_group_by_idx(struct geneve_socket *,
		    int);

static struct geneve_softc *
		geneve_socket_lookup_softc_locked(struct geneve_socket *,
		    uint32_t, uint64_t);
static struct geneve_softc *
		geneve_socket_lookup_softc(struct geneve_socket *, uint32_t,
		    uint64_t);
static int	geneve_socket_insert_softc(struct geneve_socket *,
		    struct geneve_softc *);
static void	geneve_socket_remove_softc(struct geneve_socket *,
		    struct geneve_softc *);

static struct ifnet *
		geneve_multicast_if_ref(struct geneve_softc *, int);
static void	geneve_free_multicast(struct geneve_softc *);
static int	geneve_setup_multicast_interface(struct geneve_softc *);

static int	geneve_setup_multicast(struct geneve_softc *);
static int	geneve_setup_socket(struct geneve_softc *);
#ifdef INET6
static void	geneve_setup_zero_checksum_port(struct geneve_softc *);
#endif
static void	geneve_setup_interface_hdrlen(struct geneve_softc *);
static int	geneve_valid_init_config(struct geneve_softc *);
static void	geneve_init_wait(struct geneve_softc *);
static void	geneve_init_complete(struct geneve_softc *);
static void	geneve_init(void *);
static void	geneve_release(struct geneve_softc *);
static void	geneve_teardown_wait(struct geneve_softc *);
static void	geneve_teardown_complete(struct geneve_softc *);
static void	geneve_teardown_locked(struct geneve_softc *);
static void	geneve_teardown(struct geneve_softc *);
static void	geneve_ifdetach(struct geneve_softc *, struct ifnet *,
		    struct geneve_softc_head *);
static void	geneve_timer(void *);

static int	geneve_ctrl_get_config(struct geneve_softc *, void *);
static int	geneve_ctrl_set_vni(struct geneve_softc *, void *);
static int	geneve_ctrl_set_aws_eni_id(struct geneve_softc *, void *);
static int	geneve_ctrl_set_local_addr(struct geneve_softc *, void *);
static int	geneve_ctrl_set_remote_addr(struct geneve_softc *, void *);
static int	geneve_ctrl_set_local_port(struct geneve_softc *, void *);
static int	geneve_ctrl_set_remote_port(struct geneve_softc *, void *);
static int	geneve_ctrl_set_port_range(struct geneve_softc *, void *);
static int	geneve_ctrl_set_ftable_timeout(struct geneve_softc *, void *);
static int	geneve_ctrl_set_ftable_max(struct geneve_softc *, void *);
static int	geneve_ctrl_set_multicast_if(struct geneve_softc * , void *);
static int	geneve_ctrl_set_ttl(struct geneve_softc *, void *);
static int	geneve_ctrl_set_learn(struct geneve_softc *, void *);
static int	geneve_ctrl_set_ether(struct geneve_softc *, void *);
static int	geneve_ctrl_ftable_entry_add(struct geneve_softc *, void *);
static int	geneve_ctrl_ftable_entry_rem(struct geneve_softc *, void *);
static int	geneve_ctrl_flush(struct geneve_softc *, void *);
static int	geneve_ioctl_drvspec(struct geneve_softc *,
		    struct ifdrv *, int);
static int	geneve_ioctl_ifflags(struct geneve_softc *);
static int	geneve_ioctl(struct ifnet *, u_long, caddr_t);

#if defined(INET) || defined(INET6)
static uint16_t geneve_pick_source_port(struct geneve_softc *, struct mbuf *);
static void	geneve_encap_header(struct geneve_softc *, struct mbuf *,
		    int, uint16_t, uint16_t, uint16_t);
#endif
static int	geneve_encap4(struct geneve_softc *,
		    const union geneve_sockaddr *, struct mbuf *, uint16_t);
static int	geneve_encap6(struct geneve_softc *,
		    const union geneve_sockaddr *, struct mbuf *, uint16_t);
static int	geneve_transmit(struct ifnet *, struct mbuf *);
static void	geneve_qflush(struct ifnet *);
static void	geneve_rcv_udp_packet(struct mbuf *, int, struct inpcb *,
		    const struct sockaddr *, void *);
static int	geneve_input(struct geneve_socket *, uint32_t, uint64_t,
		    uint16_t, struct mbuf **, const struct sockaddr *);

static int	geneve_stats_alloc(struct geneve_softc *);
static void	geneve_stats_free(struct geneve_softc *);
static void	geneve_set_default_config(struct geneve_softc *);
static int	geneve_set_user_config(struct geneve_softc *,
		     struct ifgeneveparam *);
static int	geneve_set_reqcap(struct geneve_softc *, struct ifnet *, int);
static void	geneve_set_hwcaps(struct geneve_softc *);
static int	geneve_clone_create(struct if_clone *, int, caddr_t);
static void	geneve_clone_destroy(struct ifnet *);

static uint32_t geneve_mac_hash(struct geneve_softc *, const uint8_t *);
static int	geneve_media_change(struct ifnet *);
static void	geneve_media_status(struct ifnet *, struct ifmediareq *);

static int	geneve_sockaddr_cmp(const union geneve_sockaddr *,
		    const struct sockaddr *);
static void	geneve_sockaddr_copy(union geneve_sockaddr *,
		    const struct sockaddr *);
static int	geneve_sockaddr_in_equal(const union geneve_sockaddr *,
		    const struct sockaddr *);
static void	geneve_sockaddr_in_copy(union geneve_sockaddr *,
		    const struct sockaddr *);
static int	geneve_sockaddr_supported(const union geneve_sockaddr *, int);
static int	geneve_sockaddr_in_any(const union geneve_sockaddr *);
static int	geneve_sockaddr_in_multicast(const union geneve_sockaddr *);
static int	geneve_sockaddr_in6_embedscope(union geneve_sockaddr *);

static int	geneve_can_change_config(struct geneve_softc *);
static int	geneve_check_vni(uint32_t);
static int	geneve_check_ttl(int);
static int	geneve_check_ftable_timeout(uint32_t);
static int	geneve_check_ftable_max(uint32_t);

static void	geneve_sysctl_setup(struct geneve_softc *);
static void	geneve_sysctl_destroy(struct geneve_softc *);
#if 0
static int	geneve_tunable_int(struct geneve_softc *, const char *, int);
#endif

static void	geneve_ifdetach_event(void *, struct ifnet *);
static void	geneve_load(void);
static void	geneve_unload(void);
static int	geneve_modevent(module_t, int, void *);

static const char geneve_name[] = "geneve";
static MALLOC_DEFINE(M_GENEVE, geneve_name,
    "Virtual eXtensible LAN Interface");
static struct if_clone *geneve_cloner;

static struct mtx geneve_list_mtx;
#define GENEVE_LIST_LOCK()	mtx_lock(&geneve_list_mtx)
#define GENEVE_LIST_UNLOCK()	mtx_unlock(&geneve_list_mtx)

static LIST_HEAD(, geneve_socket) geneve_socket_list;

static eventhandler_tag geneve_ifdetach_event_tag;

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, geneve, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Virtual eXtensible Local Area Network");

static int geneve_legacy_port = 0;
TUNABLE_INT("net.link.geneve.legacy_port", &geneve_legacy_port);
static int geneve_reuse_port = 0;
TUNABLE_INT("net.link.geneve.reuse_port", &geneve_reuse_port);

/* Default maximum number of addresses in the forwarding table. */
#ifndef GENEVE_FTABLE_MAX
#define GENEVE_FTABLE_MAX	2000
#endif

/* Timeout (in seconds) of addresses learned in the forwarding table. */
#ifndef GENEVE_FTABLE_TIMEOUT
#define GENEVE_FTABLE_TIMEOUT	(20 * 60)
#endif

/*
 * Maximum timeout (in seconds) of addresses learned in the forwarding
 * table.
 */
#ifndef GENEVE_FTABLE_MAX_TIMEOUT
#define GENEVE_FTABLE_MAX_TIMEOUT	(60 * 60 * 24)
#endif

/* Number of seconds between pruning attempts of the forwarding table. */
#ifndef GENEVE_FTABLE_PRUNE
#define GENEVE_FTABLE_PRUNE	(5 * 60)
#endif

static int geneve_ftable_prune_period = GENEVE_FTABLE_PRUNE;

struct geneve_control {
	int	(*gnvc_func)(struct geneve_softc *, void *);
	int	gnvc_argsize;
	int	gnvc_flags;
#define GENEVE_CTRL_FLAG_COPYIN	0x01
#define GENEVE_CTRL_FLAG_COPYOUT	0x02
#define GENEVE_CTRL_FLAG_SUSER	0x04
};

static const struct geneve_control geneve_control_table[] = {
	[GENEVE_CMD_GET_CONFIG] =
	    {	geneve_ctrl_get_config, sizeof(struct ifgenevecfg),
		GENEVE_CTRL_FLAG_COPYOUT
	    },

	[GENEVE_CMD_SET_VNI] =
	    {   geneve_ctrl_set_vni, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_LOCAL_ADDR] =
	    {   geneve_ctrl_set_local_addr, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_REMOTE_ADDR] =
	    {   geneve_ctrl_set_remote_addr, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_LOCAL_PORT] =
	    {   geneve_ctrl_set_local_port, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_REMOTE_PORT] =
	    {   geneve_ctrl_set_remote_port, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_PORT_RANGE] =
	    {   geneve_ctrl_set_port_range, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_FTABLE_TIMEOUT] =
	    {	geneve_ctrl_set_ftable_timeout, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_FTABLE_MAX] =
	    {	geneve_ctrl_set_ftable_max, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_MULTICAST_IF] =
	    {	geneve_ctrl_set_multicast_if, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_TTL] =
	    {	geneve_ctrl_set_ttl, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_LEARN] =
	    {	geneve_ctrl_set_learn, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_FTABLE_ENTRY_ADD] =
	    {	geneve_ctrl_ftable_entry_add, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_FTABLE_ENTRY_REM] =
	    {	geneve_ctrl_ftable_entry_rem, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_FLUSH] =
	    {   geneve_ctrl_flush, sizeof(struct ifgenevecmd),
		GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_AWS_ENI_ID] =
	    {   geneve_ctrl_set_aws_eni_id, sizeof(struct ifgenevecmd),
	        GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

	[GENEVE_CMD_SET_ETHER] =
	    {   geneve_ctrl_set_ether, sizeof(struct ifgenevecmd),
	        GENEVE_CTRL_FLAG_COPYIN | GENEVE_CTRL_FLAG_SUSER,
	    },

};

static const int geneve_control_table_size = nitems(geneve_control_table);

static int
geneve_ftable_addr_cmp(const uint8_t *a, const uint8_t *b)
{
	int i, d;

	for (i = 0, d = 0; i < ETHER_ADDR_LEN && d == 0; i++)
		d = ((int)a[i]) - ((int)b[i]);

	return (d);
}

static void
geneve_ftable_init(struct geneve_softc *sc)
{
	int i;

	sc->gnv_ftable = malloc(sizeof(struct geneve_ftable_head) *
	    GENEVE_SC_FTABLE_SIZE, M_GENEVE, M_ZERO | M_WAITOK);

	for (i = 0; i < GENEVE_SC_FTABLE_SIZE; i++)
		LIST_INIT(&sc->gnv_ftable[i]);
	sc->gnv_ftable_hash_key = arc4random();
}

static void
geneve_ftable_fini(struct geneve_softc *sc)
{
	int i;

	for (i = 0; i < GENEVE_SC_FTABLE_SIZE; i++) {
		KASSERT(LIST_EMPTY(&sc->gnv_ftable[i]),
		    ("%s: geneve %p ftable[%d] not empty", __func__, sc, i));
	}
	MPASS(sc->gnv_ftable_cnt == 0);

	free(sc->gnv_ftable, M_GENEVE);
	sc->gnv_ftable = NULL;
}

static void
geneve_ftable_flush(struct geneve_softc *sc, int all)
{
	struct geneve_ftable_entry *fe, *tfe;
	int i;

	for (i = 0; i < GENEVE_SC_FTABLE_SIZE; i++) {
		LIST_FOREACH_SAFE(fe, &sc->gnv_ftable[i], gnvfe_hash, tfe) {
			if (all || GENEVE_FE_IS_DYNAMIC(fe))
				geneve_ftable_entry_destroy(sc, fe);
		}
	}
}

static void
geneve_ftable_expire(struct geneve_softc *sc)
{
	struct geneve_ftable_entry *fe, *tfe;
	int i;

	GENEVE_LOCK_WASSERT(sc);

	for (i = 0; i < GENEVE_SC_FTABLE_SIZE; i++) {
		LIST_FOREACH_SAFE(fe, &sc->gnv_ftable[i], gnvfe_hash, tfe) {
			if (GENEVE_FE_IS_DYNAMIC(fe) &&
			    time_uptime >= fe->gnvfe_expire)
				geneve_ftable_entry_destroy(sc, fe);
		}
	}
}

static int
geneve_ftable_update_locked(struct geneve_softc *sc,
    const union geneve_sockaddr *gnvsa, const uint8_t *mac,
    struct rm_priotracker *tracker)
{
	struct geneve_ftable_entry *fe;
	int error __unused;

	GENEVE_LOCK_ASSERT(sc);

again:
	/*
	 * A forwarding entry for this MAC address might already exist. If
	 * so, update it, otherwise create a new one. We may have to upgrade
	 * the lock if we have to change or create an entry.
	 */
	fe = geneve_ftable_entry_lookup(sc, mac);
	if (fe != NULL) {
		fe->gnvfe_expire = time_uptime + sc->gnv_ftable_timeout;

		if (!GENEVE_FE_IS_DYNAMIC(fe) ||
		    geneve_sockaddr_in_equal(&fe->gnvfe_raddr, &gnvsa->sa))
			return (0);
		if (!GENEVE_LOCK_WOWNED(sc)) {
			GENEVE_RUNLOCK(sc, tracker);
			GENEVE_WLOCK(sc);
			sc->gnv_stats.ftable_lock_upgrade_failed++;
			goto again;
		}
		geneve_sockaddr_in_copy(&fe->gnvfe_raddr, &gnvsa->sa);
		return (0);
	}

	if (!GENEVE_LOCK_WOWNED(sc)) {
		GENEVE_RUNLOCK(sc, tracker);
		GENEVE_WLOCK(sc);
		sc->gnv_stats.ftable_lock_upgrade_failed++;
		goto again;
	}

	if (sc->gnv_ftable_cnt >= sc->gnv_ftable_max) {
		sc->gnv_stats.ftable_nospace++;
		return (ENOSPC);
	}

	fe = geneve_ftable_entry_alloc();
	if (fe == NULL)
		return (ENOMEM);

	geneve_ftable_entry_init(sc, fe, mac, &gnvsa->sa, GENEVE_FE_FLAG_DYNAMIC);

	/* The prior lookup failed, so the insert should not. */
	error = geneve_ftable_entry_insert(sc, fe);
	MPASS(error == 0);

	return (0);
}

static int
geneve_ftable_learn(struct geneve_softc *sc, const struct sockaddr *sa,
    const uint8_t *mac)
{
	struct rm_priotracker tracker;
	union geneve_sockaddr gnvsa;
	int error;

	/*
	 * The source port may be randomly selected by the remote host, so
	 * use the port of the default destination address.
	 */
	geneve_sockaddr_copy(&gnvsa, sa);
	gnvsa.in4.sin_port = sc->gnv_dst_addr.in4.sin_port;

	if (GENEVE_SOCKADDR_IS_IPV6(&gnvsa)) {
		error = geneve_sockaddr_in6_embedscope(&gnvsa);
		if (error)
			return (error);
	}

	GENEVE_RLOCK(sc, &tracker);
	error = geneve_ftable_update_locked(sc, &gnvsa, mac, &tracker);
	GENEVE_UNLOCK(sc, &tracker);

	return (error);
}

static int
geneve_ftable_sysctl_dump(SYSCTL_HANDLER_ARGS)
{
	struct rm_priotracker tracker;
	struct sbuf sb;
	struct geneve_softc *sc;
	struct geneve_ftable_entry *fe;
	size_t size;
	int i, error;

	/*
	 * This is mostly intended for debugging during development. It is
	 * not practical to dump an entire large table this way.
	 */

	sc = arg1;
	size = PAGE_SIZE;	/* Calculate later. */

	sbuf_new(&sb, NULL, size, SBUF_FIXEDLEN);
	sbuf_putc(&sb, '\n');

	GENEVE_RLOCK(sc, &tracker);
	for (i = 0; i < GENEVE_SC_FTABLE_SIZE; i++) {
		LIST_FOREACH(fe, &sc->gnv_ftable[i], gnvfe_hash) {
			if (sbuf_error(&sb) != 0)
				break;
			geneve_ftable_entry_dump(fe, &sb);
		}
	}
	GENEVE_RUNLOCK(sc, &tracker);

	if (sbuf_len(&sb) == 1)
		sbuf_setpos(&sb, 0);

	sbuf_finish(&sb);
	error = sysctl_handle_string(oidp, sbuf_data(&sb), sbuf_len(&sb), req);
	sbuf_delete(&sb);

	return (error);
}

static struct geneve_ftable_entry *
geneve_ftable_entry_alloc(void)
{
	struct geneve_ftable_entry *fe;

	fe = malloc(sizeof(*fe), M_GENEVE, M_ZERO | M_NOWAIT);

	return (fe);
}

static void
geneve_ftable_entry_free(struct geneve_ftable_entry *fe)
{

	free(fe, M_GENEVE);
}

static void
geneve_ftable_entry_init(struct geneve_softc *sc, struct geneve_ftable_entry *fe,
    const uint8_t *mac, const struct sockaddr *sa, uint32_t flags)
{

	fe->gnvfe_flags = flags;
	fe->gnvfe_expire = time_uptime + sc->gnv_ftable_timeout;
	memcpy(fe->gnvfe_mac, mac, ETHER_ADDR_LEN);
	geneve_sockaddr_copy(&fe->gnvfe_raddr, sa);
}

static void
geneve_ftable_entry_destroy(struct geneve_softc *sc,
    struct geneve_ftable_entry *fe)
{

	sc->gnv_ftable_cnt--;
	LIST_REMOVE(fe, gnvfe_hash);
	geneve_ftable_entry_free(fe);
}

static int
geneve_ftable_entry_insert(struct geneve_softc *sc,
    struct geneve_ftable_entry *fe)
{
	struct geneve_ftable_entry *lfe;
	uint32_t hash;
	int dir;

	GENEVE_LOCK_WASSERT(sc);
	hash = GENEVE_SC_FTABLE_HASH(sc, fe->gnvfe_mac);

	lfe = LIST_FIRST(&sc->gnv_ftable[hash]);
	if (lfe == NULL) {
		LIST_INSERT_HEAD(&sc->gnv_ftable[hash], fe, gnvfe_hash);
		goto out;
	}

	do {
		dir = geneve_ftable_addr_cmp(fe->gnvfe_mac, lfe->gnvfe_mac);
		if (dir == 0)
			return (EEXIST);
		if (dir > 0) {
			LIST_INSERT_BEFORE(lfe, fe, gnvfe_hash);
			goto out;
		} else if (LIST_NEXT(lfe, gnvfe_hash) == NULL) {
			LIST_INSERT_AFTER(lfe, fe, gnvfe_hash);
			goto out;
		} else
			lfe = LIST_NEXT(lfe, gnvfe_hash);
	} while (lfe != NULL);

out:
	sc->gnv_ftable_cnt++;

	return (0);
}

static struct geneve_ftable_entry *
geneve_ftable_entry_lookup(struct geneve_softc *sc, const uint8_t *mac)
{
	struct geneve_ftable_entry *fe;
	uint32_t hash;
	int dir;

	GENEVE_LOCK_ASSERT(sc);
	hash = GENEVE_SC_FTABLE_HASH(sc, mac);

	LIST_FOREACH(fe, &sc->gnv_ftable[hash], gnvfe_hash) {
		dir = geneve_ftable_addr_cmp(mac, fe->gnvfe_mac);
		if (dir == 0)
			return (fe);
		if (dir > 0)
			break;
	}

	return (NULL);
}

static void
geneve_ftable_entry_dump(struct geneve_ftable_entry *fe, struct sbuf *sb)
{
	char buf[64];
	const union geneve_sockaddr *sa;
	const void *addr;
	int i, len, af, width;

	sa = &fe->gnvfe_raddr;
	af = sa->sa.sa_family;
	len = sbuf_len(sb);

	sbuf_printf(sb, "%c 0x%02X ", GENEVE_FE_IS_DYNAMIC(fe) ? 'D' : 'S',
	    fe->gnvfe_flags);

	for (i = 0; i < ETHER_ADDR_LEN - 1; i++)
		sbuf_printf(sb, "%02X:", fe->gnvfe_mac[i]);
	sbuf_printf(sb, "%02X ", fe->gnvfe_mac[i]);

	if (af == AF_INET) {
		addr = &sa->in4.sin_addr;
		width = INET_ADDRSTRLEN - 1;
	} else {
		addr = &sa->in6.sin6_addr;
		width = INET6_ADDRSTRLEN - 1;
	}
	inet_ntop(af, addr, buf, sizeof(buf));
	sbuf_printf(sb, "%*s ", width, buf);

	sbuf_printf(sb, "%08jd", (intmax_t)fe->gnvfe_expire);

	sbuf_putc(sb, '\n');

	/* Truncate a partial line. */
	if (sbuf_error(sb) != 0)
		sbuf_setpos(sb, len);
}

static struct geneve_socket *
geneve_socket_alloc(const union geneve_sockaddr *sa)
{
	struct geneve_socket *vso;
	int i;

	vso = malloc(sizeof(*vso), M_GENEVE, M_WAITOK | M_ZERO);
	rm_init(&vso->gnvso_lock, "genevesorm");
	refcount_init(&vso->gnvso_refcnt, 0);
	for (i = 0; i < GENEVE_SO_VNI_HASH_SIZE; i++)
		LIST_INIT(&vso->gnvso_vni_hash[i]);
	vso->gnvso_laddr = *sa;

	return (vso);
}

static void
geneve_socket_destroy(struct geneve_socket *vso)
{
	struct socket *so;
#ifdef INVARIANTS
	int i;
	struct geneve_socket_mc_info *mc;

	for (i = 0; i < GENEVE_SO_MC_MAX_GROUPS; i++) {
		mc = &vso->gnvso_mc[i];
		KASSERT(mc->gnvsomc_gaddr.sa.sa_family == AF_UNSPEC,
		    ("%s: socket %p mc[%d] still has address",
		     __func__, vso, i));
	}

	for (i = 0; i < GENEVE_SO_VNI_HASH_SIZE; i++) {
		KASSERT(LIST_EMPTY(&vso->gnvso_vni_hash[i]),
		    ("%s: socket %p vni_hash[%d] not empty",
		     __func__, vso, i));
	}
#endif
	so = vso->gnvso_sock;
	if (so != NULL) {
		vso->gnvso_sock = NULL;
		soclose(so);
	}

	rm_destroy(&vso->gnvso_lock);
	free(vso, M_GENEVE);
}

static void
geneve_socket_release(struct geneve_socket *vso)
{
	int destroy;

	GENEVE_LIST_LOCK();
	destroy = GENEVE_SO_RELEASE(vso);
	if (destroy != 0)
		LIST_REMOVE(vso, gnvso_entry);
	GENEVE_LIST_UNLOCK();

	if (destroy != 0)
		geneve_socket_destroy(vso);
}

static struct geneve_socket *
geneve_socket_lookup(union geneve_sockaddr *gnvsa)
{
	struct geneve_socket *vso;

	GENEVE_LIST_LOCK();
	LIST_FOREACH(vso, &geneve_socket_list, gnvso_entry) {
		if (geneve_sockaddr_cmp(&vso->gnvso_laddr, &gnvsa->sa) == 0) {
			GENEVE_SO_ACQUIRE(vso);
			break;
		}
	}
	GENEVE_LIST_UNLOCK();

	return (vso);
}

static void
geneve_socket_insert(struct geneve_socket *vso)
{

	GENEVE_LIST_LOCK();
	GENEVE_SO_ACQUIRE(vso);
	LIST_INSERT_HEAD(&geneve_socket_list, vso, gnvso_entry);
	GENEVE_LIST_UNLOCK();
}

static int
geneve_socket_init(struct geneve_socket *vso, struct ifnet *ifp)
{
	struct thread *td;
	int error;

	td = curthread;

	error = socreate(vso->gnvso_laddr.sa.sa_family, &vso->gnvso_sock,
	    SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
	if (error) {
		if_printf(ifp, "cannot create socket: %d\n", error);
		return (error);
	}

	error = udp_set_kernel_tunneling(vso->gnvso_sock,
	    geneve_rcv_udp_packet, NULL, vso);
	if (error) {
		if_printf(ifp, "cannot set tunneling function: %d\n", error);
		return (error);
	}

	if (geneve_reuse_port != 0) {
		struct sockopt sopt;
		int val = 1;

		bzero(&sopt, sizeof(sopt));
		sopt.sopt_dir = SOPT_SET;
		sopt.sopt_level = IPPROTO_IP;
		sopt.sopt_name = SO_REUSEPORT;
		sopt.sopt_val = &val;
		sopt.sopt_valsize = sizeof(val);
		error = sosetopt(vso->gnvso_sock, &sopt);
		if (error) {
			if_printf(ifp,
			    "cannot set REUSEADDR socket opt: %d\n", error);
			return (error);
		}
	}

	return (0);
}

static int
geneve_socket_bind(struct geneve_socket *vso, struct ifnet *ifp)
{
	union geneve_sockaddr laddr;
	struct thread *td;
	int error;

	td = curthread;
	laddr = vso->gnvso_laddr;

	error = sobind(vso->gnvso_sock, &laddr.sa, td);
	if (error) {
		if (error != EADDRINUSE)
			if_printf(ifp, "cannot bind socket: %d\n", error);
		return (error);
	}

	return (0);
}

static int
geneve_socket_create(struct ifnet *ifp, int multicast,
    const union geneve_sockaddr *saddr, struct geneve_socket **vsop)
{
	union geneve_sockaddr laddr;
	struct geneve_socket *vso;
	int error;

	laddr = *saddr;

	/*
	 * If this socket will be multicast, then only the local port
	 * must be specified when binding.
	 */
	if (multicast != 0) {
		if (GENEVE_SOCKADDR_IS_IPV4(&laddr))
			laddr.in4.sin_addr.s_addr = INADDR_ANY;
#ifdef INET6
		else
			laddr.in6.sin6_addr = in6addr_any;
#endif
	}

	vso = geneve_socket_alloc(&laddr);
	if (vso == NULL)
		return (ENOMEM);

	error = geneve_socket_init(vso, ifp);
	if (error)
		goto fail;

	error = geneve_socket_bind(vso, ifp);
	if (error)
		goto fail;

	/*
	 * There is a small window between the bind completing and
	 * inserting the socket, so that a concurrent create may fail.
	 * Let's not worry about that for now.
	 */
	geneve_socket_insert(vso);
	*vsop = vso;

	return (0);

fail:
	geneve_socket_destroy(vso);

	return (error);
}

static void
geneve_socket_ifdetach(struct geneve_socket *vso, struct ifnet *ifp,
    struct geneve_softc_head *list)
{
	struct rm_priotracker tracker;
	struct geneve_softc *sc;
	int i;

	GENEVE_SO_RLOCK(vso, &tracker);
	for (i = 0; i < GENEVE_SO_VNI_HASH_SIZE; i++) {
		LIST_FOREACH(sc, &vso->gnvso_vni_hash[i], gnv_entry)
			geneve_ifdetach(sc, ifp, list);
	}
	GENEVE_SO_RUNLOCK(vso, &tracker);
}

static struct geneve_socket *
geneve_socket_mc_lookup(const union geneve_sockaddr *gnvsa)
{
	union geneve_sockaddr laddr;
	struct geneve_socket *vso;

	laddr = *gnvsa;

	if (GENEVE_SOCKADDR_IS_IPV4(&laddr))
		laddr.in4.sin_addr.s_addr = INADDR_ANY;
#ifdef INET6
	else
		laddr.in6.sin6_addr = in6addr_any;
#endif

	vso = geneve_socket_lookup(&laddr);

	return (vso);
}

static int
geneve_sockaddr_mc_info_match(const struct geneve_socket_mc_info *mc,
    const union geneve_sockaddr *group, const union geneve_sockaddr *local,
    int ifidx)
{

	if (!geneve_sockaddr_in_any(local) &&
	    !geneve_sockaddr_in_equal(&mc->gnvsomc_saddr, &local->sa))
		return (0);
	if (!geneve_sockaddr_in_equal(&mc->gnvsomc_gaddr, &group->sa))
		return (0);
	if (ifidx != 0 && ifidx != mc->gnvsomc_ifidx)
		return (0);

	return (1);
}

static int
geneve_socket_mc_join_group(struct geneve_socket *vso,
    const union geneve_sockaddr *group, const union geneve_sockaddr *local,
    int *ifidx, union geneve_sockaddr *source)
{
	struct sockopt sopt;
	int error;

	*source = *local;

	if (GENEVE_SOCKADDR_IS_IPV4(group)) {
		struct ip_mreq mreq;

		mreq.imr_multiaddr = group->in4.sin_addr;
		mreq.imr_interface = local->in4.sin_addr;

		bzero(&sopt, sizeof(sopt));
		sopt.sopt_dir = SOPT_SET;
		sopt.sopt_level = IPPROTO_IP;
		sopt.sopt_name = IP_ADD_MEMBERSHIP;
		sopt.sopt_val = &mreq;
		sopt.sopt_valsize = sizeof(mreq);
		error = sosetopt(vso->gnvso_sock, &sopt);
		if (error)
			return (error);

		/*
		 * BMV: Ideally, there would be a formal way for us to get
		 * the local interface that was selected based on the
		 * imr_interface address. We could then update *ifidx so
		 * geneve_sockaddr_mc_info_match() would return a match for
		 * later creates that explicitly set the multicast interface.
		 *
		 * If we really need to, we can of course look in the INP's
		 * membership list:
		 *     sotoinpcb(vso->gnvso_sock)->inp_moptions->
		 *         imo_head[]->imf_inm->inm_ifp
		 * similarly to imo_match_group().
		 */
		source->in4.sin_addr = local->in4.sin_addr;

	} else if (GENEVE_SOCKADDR_IS_IPV6(group)) {
		struct ipv6_mreq mreq;

		mreq.ipv6mr_multiaddr = group->in6.sin6_addr;
		mreq.ipv6mr_interface = *ifidx;

		bzero(&sopt, sizeof(sopt));
		sopt.sopt_dir = SOPT_SET;
		sopt.sopt_level = IPPROTO_IPV6;
		sopt.sopt_name = IPV6_JOIN_GROUP;
		sopt.sopt_val = &mreq;
		sopt.sopt_valsize = sizeof(mreq);
		error = sosetopt(vso->gnvso_sock, &sopt);
		if (error)
			return (error);

		/*
		 * BMV: As with IPv4, we would really like to know what
		 * interface in6p_lookup_mcast_ifp() selected.
		 */
	} else
		error = EAFNOSUPPORT;

	return (error);
}

static int
geneve_socket_mc_leave_group(struct geneve_socket *vso,
    const union geneve_sockaddr *group, const union geneve_sockaddr *source,
    int ifidx)
{
	struct sockopt sopt;
	int error;

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;

	if (GENEVE_SOCKADDR_IS_IPV4(group)) {
		struct ip_mreq mreq;

		mreq.imr_multiaddr = group->in4.sin_addr;
		mreq.imr_interface = source->in4.sin_addr;

		sopt.sopt_level = IPPROTO_IP;
		sopt.sopt_name = IP_DROP_MEMBERSHIP;
		sopt.sopt_val = &mreq;
		sopt.sopt_valsize = sizeof(mreq);
		error = sosetopt(vso->gnvso_sock, &sopt);

	} else if (GENEVE_SOCKADDR_IS_IPV6(group)) {
		struct ipv6_mreq mreq;

		mreq.ipv6mr_multiaddr = group->in6.sin6_addr;
		mreq.ipv6mr_interface = ifidx;

		sopt.sopt_level = IPPROTO_IPV6;
		sopt.sopt_name = IPV6_LEAVE_GROUP;
		sopt.sopt_val = &mreq;
		sopt.sopt_valsize = sizeof(mreq);
		error = sosetopt(vso->gnvso_sock, &sopt);

	} else
		error = EAFNOSUPPORT;

	return (error);
}

static int
geneve_socket_mc_add_group(struct geneve_socket *vso,
    const union geneve_sockaddr *group, const union geneve_sockaddr *local,
    int ifidx, int *idx)
{
	union geneve_sockaddr source;
	struct geneve_socket_mc_info *mc;
	int i, empty, error;

	/*
	 * Within a socket, the same multicast group may be used by multiple
	 * interfaces, each with a different network identifier. But a socket
	 * may only join a multicast group once, so keep track of the users
	 * here.
	 */

	GENEVE_SO_WLOCK(vso);
	for (empty = 0, i = 0; i < GENEVE_SO_MC_MAX_GROUPS; i++) {
		mc = &vso->gnvso_mc[i];

		if (mc->gnvsomc_gaddr.sa.sa_family == AF_UNSPEC) {
			empty++;
			continue;
		}

		if (geneve_sockaddr_mc_info_match(mc, group, local, ifidx))
			goto out;
	}
	GENEVE_SO_WUNLOCK(vso);

	if (empty == 0)
		return (ENOSPC);

	error = geneve_socket_mc_join_group(vso, group, local, &ifidx, &source);
	if (error)
		return (error);

	GENEVE_SO_WLOCK(vso);
	for (i = 0; i < GENEVE_SO_MC_MAX_GROUPS; i++) {
		mc = &vso->gnvso_mc[i];

		if (mc->gnvsomc_gaddr.sa.sa_family == AF_UNSPEC) {
			geneve_sockaddr_copy(&mc->gnvsomc_gaddr, &group->sa);
			geneve_sockaddr_copy(&mc->gnvsomc_saddr, &source.sa);
			mc->gnvsomc_ifidx = ifidx;
			goto out;
		}
	}
	GENEVE_SO_WUNLOCK(vso);

	error = geneve_socket_mc_leave_group(vso, group, &source, ifidx);
	MPASS(error == 0);

	return (ENOSPC);

out:
	mc->gnvsomc_users++;
	GENEVE_SO_WUNLOCK(vso);

	*idx = i;

	return (0);
}

static void
geneve_socket_mc_release_group_by_idx(struct geneve_socket *vso, int idx)
{
	union geneve_sockaddr group, source;
	struct geneve_socket_mc_info *mc;
	int ifidx, leave;

	KASSERT(idx >= 0 && idx < GENEVE_SO_MC_MAX_GROUPS,
	    ("%s: vso %p idx %d out of bounds", __func__, vso, idx));

	leave = 0;
	mc = &vso->gnvso_mc[idx];

	GENEVE_SO_WLOCK(vso);
	mc->gnvsomc_users--;
	if (mc->gnvsomc_users == 0) {
		group = mc->gnvsomc_gaddr;
		source = mc->gnvsomc_saddr;
		ifidx = mc->gnvsomc_ifidx;
		bzero(mc, sizeof(*mc));
		leave = 1;
	}
	GENEVE_SO_WUNLOCK(vso);

	if (leave != 0) {
		/*
		 * Our socket's membership in this group may have already
		 * been removed if we joined through an interface that's
		 * been detached.
		 */
		geneve_socket_mc_leave_group(vso, &group, &source, ifidx);
	}
}

static struct geneve_softc *
geneve_socket_lookup_softc_locked(struct geneve_socket *vso, uint32_t vni,
    uint64_t aws_eni_id)
{
	struct geneve_softc *sc;
	uint32_t hash;

	GENEVE_SO_LOCK_ASSERT(vso);
	hash = GENEVE_SO_VNI_HASH(vni, aws_eni_id);

	LIST_FOREACH(sc, &vso->gnvso_vni_hash[hash], gnv_entry) {
		if (sc->gnv_vni == vni) {
			if (vni == 0 && aws_eni_id != 0 &&
			    aws_eni_id != sc->gnv_aws_eni_id) {
				continue;
			}
			GENEVE_ACQUIRE(sc);
			break;
		}
	}

	return (sc);
}

static struct geneve_softc *
geneve_socket_lookup_softc(struct geneve_socket *vso, uint32_t vni,
    uint64_t aws_eni_id)
{
	struct rm_priotracker tracker;
	struct geneve_softc *sc;

	GENEVE_SO_RLOCK(vso, &tracker);
	sc = geneve_socket_lookup_softc_locked(vso, vni, aws_eni_id);
	GENEVE_SO_RUNLOCK(vso, &tracker);

	return (sc);
}

static int
geneve_socket_insert_softc(struct geneve_socket *vso, struct geneve_softc *sc)
{
	struct geneve_softc *tsc;
	uint32_t vni, hash;
	uint64_t aws_eni_id;

	vni = sc->gnv_vni;
	aws_eni_id = sc->gnv_aws_eni_id;
	hash = GENEVE_SO_VNI_HASH(vni, aws_eni_id);

	GENEVE_SO_WLOCK(vso);
	tsc = geneve_socket_lookup_softc_locked(vso, vni, aws_eni_id);
	if (tsc != NULL) {
		GENEVE_SO_WUNLOCK(vso);
		geneve_release(tsc);
		return (EEXIST);
	}

	GENEVE_ACQUIRE(sc);
	LIST_INSERT_HEAD(&vso->gnvso_vni_hash[hash], sc, gnv_entry);
	GENEVE_SO_WUNLOCK(vso);

	return (0);
}

static void
geneve_socket_remove_softc(struct geneve_socket *vso, struct geneve_softc *sc)
{

	GENEVE_SO_WLOCK(vso);
	LIST_REMOVE(sc, gnv_entry);
	GENEVE_SO_WUNLOCK(vso);

	geneve_release(sc);
}

static struct ifnet *
geneve_multicast_if_ref(struct geneve_softc *sc, int ipv4)
{
	struct ifnet *ifp;

	GENEVE_LOCK_ASSERT(sc);

	if (ipv4 && sc->gnv_im4o != NULL)
		ifp = sc->gnv_im4o->imo_multicast_ifp;
	else if (!ipv4 && sc->gnv_im6o != NULL)
		ifp = sc->gnv_im6o->im6o_multicast_ifp;
	else
		ifp = NULL;

	if (ifp != NULL)
		if_ref(ifp);

	return (ifp);
}

static void
geneve_free_multicast(struct geneve_softc *sc)
{

	if (sc->gnv_mc_ifp != NULL) {
		if_rele(sc->gnv_mc_ifp);
		sc->gnv_mc_ifp = NULL;
		sc->gnv_mc_ifindex = 0;
	}

	if (sc->gnv_im4o != NULL) {
		free(sc->gnv_im4o, M_GENEVE);
		sc->gnv_im4o = NULL;
	}

	if (sc->gnv_im6o != NULL) {
		free(sc->gnv_im6o, M_GENEVE);
		sc->gnv_im6o = NULL;
	}
}

static int
geneve_setup_multicast_interface(struct geneve_softc *sc)
{
	struct ifnet *ifp;

	ifp = ifunit_ref(sc->gnv_mc_ifname);
	if (ifp == NULL) {
		if_printf(sc->gnv_ifp, "multicast interface %s does "
		    "not exist\n", sc->gnv_mc_ifname);
		return (ENOENT);
	}

	if ((ifp->if_flags & IFF_MULTICAST) == 0) {
		if_printf(sc->gnv_ifp, "interface %s does not support "
		     "multicast\n", sc->gnv_mc_ifname);
		if_rele(ifp);
		return (ENOTSUP);
	}

	sc->gnv_mc_ifp = ifp;
	sc->gnv_mc_ifindex = ifp->if_index;

	return (0);
}

static int
geneve_setup_multicast(struct geneve_softc *sc)
{
	const union geneve_sockaddr *group;
	int error;

	group = &sc->gnv_dst_addr;
	error = 0;

	if (sc->gnv_mc_ifname[0] != '\0') {
		error = geneve_setup_multicast_interface(sc);
		if (error)
			return (error);
	}

	/*
	 * Initialize an multicast options structure that is sufficiently
	 * populated for use in the respective IP output routine. This
	 * structure is typically stored in the socket, but our sockets
	 * may be shared among multiple interfaces.
	 */
	if (GENEVE_SOCKADDR_IS_IPV4(group)) {
		sc->gnv_im4o = malloc(sizeof(struct ip_moptions), M_GENEVE,
		    M_ZERO | M_WAITOK);
		sc->gnv_im4o->imo_multicast_ifp = sc->gnv_mc_ifp;
		sc->gnv_im4o->imo_multicast_ttl = sc->gnv_ttl;
		sc->gnv_im4o->imo_multicast_vif = -1;
	} else if (GENEVE_SOCKADDR_IS_IPV6(group)) {
		sc->gnv_im6o = malloc(sizeof(struct ip6_moptions), M_GENEVE,
		    M_ZERO | M_WAITOK);
		sc->gnv_im6o->im6o_multicast_ifp = sc->gnv_mc_ifp;
		sc->gnv_im6o->im6o_multicast_hlim = sc->gnv_ttl;
	}

	return (error);
}

static int
geneve_setup_socket(struct geneve_softc *sc)
{
	struct geneve_socket *vso;
	struct ifnet *ifp;
	union geneve_sockaddr *saddr, *daddr;
	int multicast, error;

	vso = NULL;
	ifp = sc->gnv_ifp;
	saddr = &sc->gnv_src_addr;
	daddr = &sc->gnv_dst_addr;

	multicast = geneve_sockaddr_in_multicast(daddr);
	MPASS(multicast != -1);
	sc->gnv_vso_mc_index = -1;

	/*
	 * Try to create the socket. If that fails, attempt to use an
	 * existing socket.
	 */
	error = geneve_socket_create(ifp, multicast, saddr, &vso);
	if (error) {
		if (multicast != 0)
			vso = geneve_socket_mc_lookup(saddr);
		else
			vso = geneve_socket_lookup(saddr);

		if (vso == NULL) {
			if_printf(ifp, "cannot create socket (error: %d), "
			    "and no existing socket found\n", error);
			goto out;
		}
	}

	if (multicast != 0) {
		error = geneve_setup_multicast(sc);
		if (error)
			goto out;

		error = geneve_socket_mc_add_group(vso, daddr, saddr,
		    sc->gnv_mc_ifindex, &sc->gnv_vso_mc_index);
		if (error)
			goto out;
	}

	sc->gnv_sock = vso;
	error = geneve_socket_insert_softc(vso, sc);
	if (error) {
		sc->gnv_sock = NULL;
		if (sc->gnv_aws_eni_id != 0) {
			if_printf(ifp, "AWS ENI ID %lu already exists in "
			    "this socket\n", sc->gnv_aws_eni_id);
			goto out;
		}

		if_printf(ifp, "network identifier %d already exists in "
		    "this socket\n", sc->gnv_vni);
		goto out;
	}

	return (0);

out:
	if (vso != NULL) {
		if (sc->gnv_vso_mc_index != -1) {
			geneve_socket_mc_release_group_by_idx(vso,
			    sc->gnv_vso_mc_index);
			sc->gnv_vso_mc_index = -1;
		}
		if (multicast != 0)
			geneve_free_multicast(sc);
		geneve_socket_release(vso);
	}

	return (error);
}

#ifdef INET6
static void
geneve_setup_zero_checksum_port(struct geneve_softc *sc)
{

	if (!GENEVE_SOCKADDR_IS_IPV6(&sc->gnv_src_addr))
		return;

	MPASS(sc->gnv_src_addr.in6.sin6_port != 0);
	MPASS(sc->gnv_dst_addr.in6.sin6_port != 0);

	if (sc->gnv_src_addr.in6.sin6_port != sc->gnv_dst_addr.in6.sin6_port) {
		if_printf(sc->gnv_ifp, "port %d in src address does not match "
		    "port %d in dst address, rfc6935_port (%d) not updated.\n",
		    ntohs(sc->gnv_src_addr.in6.sin6_port),
		    ntohs(sc->gnv_dst_addr.in6.sin6_port),
		    V_zero_checksum_port);
		return;
	}

	if (V_zero_checksum_port != 0) {
		if (V_zero_checksum_port !=
		    ntohs(sc->gnv_src_addr.in6.sin6_port)) {
			if_printf(sc->gnv_ifp, "rfc6935_port is already set to "
			    "%d, cannot set it to %d.\n", V_zero_checksum_port,
			    ntohs(sc->gnv_src_addr.in6.sin6_port));
		}
		return;
	}

	V_zero_checksum_port = ntohs(sc->gnv_src_addr.in6.sin6_port);
	if_printf(sc->gnv_ifp, "rfc6935_port set to %d\n",
	    V_zero_checksum_port);
}
#endif

static void
geneve_setup_interface_hdrlen(struct geneve_softc *sc)
{
	struct ifnet *ifp;

	ifp = sc->gnv_ifp;
	ifp->if_hdrlen = ETHER_HDR_LEN + sizeof(struct geneveudphdr);

	if (GENEVE_SOCKADDR_IS_IPV4(&sc->gnv_dst_addr) != 0)
		ifp->if_hdrlen += sizeof(struct ip);
	else if (GENEVE_SOCKADDR_IS_IPV6(&sc->gnv_dst_addr) != 0)
		ifp->if_hdrlen += sizeof(struct ip6_hdr);
}

static int
geneve_valid_init_config(struct geneve_softc *sc)
{
	const char *reason;

	if (geneve_check_vni(sc->gnv_vni) != 0) {
		reason = "invalid virtual network identifier specified";
		goto fail;
	}

	if (geneve_sockaddr_supported(&sc->gnv_src_addr, 1) == 0) {
		reason = "source address type is not supported";
		goto fail;
	}

	if (geneve_sockaddr_supported(&sc->gnv_dst_addr, 0) == 0) {
		reason = "destination address type is not supported";
		goto fail;
	}

	if (geneve_sockaddr_in_any(&sc->gnv_dst_addr) != 0) {
		reason = "no valid destination address specified";
		goto fail;
	}

	if (geneve_sockaddr_in_multicast(&sc->gnv_dst_addr) == 0 &&
	    sc->gnv_mc_ifname[0] != '\0') {
		reason = "can only specify interface with a group address";
		goto fail;
	}

	if (geneve_sockaddr_in_any(&sc->gnv_src_addr) == 0) {
		if (GENEVE_SOCKADDR_IS_IPV4(&sc->gnv_src_addr) ^
		    GENEVE_SOCKADDR_IS_IPV4(&sc->gnv_dst_addr)) {
			reason = "source and destination address must both "
			    "be either IPv4 or IPv6";
			goto fail;
		}
	}

	if (sc->gnv_src_addr.in4.sin_port == 0) {
		reason = "local port not specified";
		goto fail;
	}

	if (sc->gnv_dst_addr.in4.sin_port == 0) {
		reason = "remote port not specified";
		goto fail;
	}

	return (0);

fail:
	if_printf(sc->gnv_ifp, "cannot initialize interface: %s\n", reason);
	return (EINVAL);
}

static void
geneve_init_wait(struct geneve_softc *sc)
{

	GENEVE_LOCK_WASSERT(sc);
	while (sc->gnv_flags & GENEVE_FLAG_INIT)
		rm_sleep(sc, &sc->gnv_lock, 0, "gnvint", hz);
}

static void
geneve_init_complete(struct geneve_softc *sc)
{

	GENEVE_WLOCK(sc);
	sc->gnv_flags &= ~GENEVE_FLAG_INIT;
	wakeup(sc);
	GENEVE_WUNLOCK(sc);
}

static void
geneve_init(void *xsc)
{
	static const uint8_t empty_mac[ETHER_ADDR_LEN];
	struct geneve_softc *sc;
	struct ifnet *ifp;

	sc = xsc;
	ifp = sc->gnv_ifp;

	sx_xlock(&geneve_sx);
	GENEVE_WLOCK(sc);
	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		GENEVE_WUNLOCK(sc);
		sx_xunlock(&geneve_sx);
		return;
	}
	sc->gnv_flags |= GENEVE_FLAG_INIT;
	GENEVE_WUNLOCK(sc);

	if (geneve_valid_init_config(sc) != 0)
		goto out;

	if (geneve_setup_socket(sc) != 0)
		goto out;

#ifdef INET6
	geneve_setup_zero_checksum_port(sc);
#endif

	/* Initialize the default forwarding entry. */
	geneve_ftable_entry_init(sc, &sc->gnv_default_fe, empty_mac,
	    &sc->gnv_dst_addr.sa, GENEVE_FE_FLAG_STATIC);

	GENEVE_WLOCK(sc);
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	callout_reset(&sc->gnv_callout, geneve_ftable_prune_period * hz,
	    geneve_timer, sc);
	GENEVE_WUNLOCK(sc);

	if_link_state_change(ifp, LINK_STATE_UP);

	EVENTHANDLER_INVOKE(geneve_start, ifp, sc->gnv_src_addr.in4.sin_family,
	    ntohs(sc->gnv_src_addr.in4.sin_port));
out:
	geneve_init_complete(sc);
	sx_xunlock(&geneve_sx);
}

static void
geneve_release(struct geneve_softc *sc)
{

	/*
	 * The softc may be destroyed as soon as we release our reference,
	 * so we cannot serialize the wakeup with the softc lock. We use a
	 * timeout in our sleeps so a missed wakeup is unfortunate but not
	 * fatal.
	 */
	if (GENEVE_RELEASE(sc) != 0)
		wakeup(sc);
}

static void
geneve_teardown_wait(struct geneve_softc *sc)
{

	GENEVE_LOCK_WASSERT(sc);
	while (sc->gnv_flags & GENEVE_FLAG_TEARDOWN)
		rm_sleep(sc, &sc->gnv_lock, 0, "gnvtrn", hz);
}

static void
geneve_teardown_complete(struct geneve_softc *sc)
{

	GENEVE_WLOCK(sc);
	sc->gnv_flags &= ~GENEVE_FLAG_TEARDOWN;
	wakeup(sc);
	GENEVE_WUNLOCK(sc);
}

static void
geneve_teardown_locked(struct geneve_softc *sc)
{
	struct ifnet *ifp;
	struct geneve_socket *vso;

	sx_assert(&geneve_sx, SA_XLOCKED);
	GENEVE_LOCK_WASSERT(sc);
	MPASS(sc->gnv_flags & GENEVE_FLAG_TEARDOWN);

	ifp = sc->gnv_ifp;
	ifp->if_flags &= ~IFF_UP;
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	callout_stop(&sc->gnv_callout);
	vso = sc->gnv_sock;
	sc->gnv_sock = NULL;

	GENEVE_WUNLOCK(sc);
	if_link_state_change(ifp, LINK_STATE_DOWN);
	EVENTHANDLER_INVOKE(geneve_stop, ifp, sc->gnv_src_addr.in4.sin_family,
	    ntohs(sc->gnv_src_addr.in4.sin_port));

	if (vso != NULL) {
		geneve_socket_remove_softc(vso, sc);

		if (sc->gnv_vso_mc_index != -1) {
			geneve_socket_mc_release_group_by_idx(vso,
			    sc->gnv_vso_mc_index);
			sc->gnv_vso_mc_index = -1;
		}
	}

	GENEVE_WLOCK(sc);
	while (sc->gnv_refcnt != 0)
		rm_sleep(sc, &sc->gnv_lock, 0, "gnvdrn", hz);
	GENEVE_WUNLOCK(sc);

	callout_drain(&sc->gnv_callout);

	geneve_free_multicast(sc);
	if (vso != NULL)
		geneve_socket_release(vso);

	geneve_teardown_complete(sc);
}

static void
geneve_teardown(struct geneve_softc *sc)
{

	sx_xlock(&geneve_sx);
	GENEVE_WLOCK(sc);
	if (sc->gnv_flags & GENEVE_FLAG_TEARDOWN) {
		geneve_teardown_wait(sc);
		GENEVE_WUNLOCK(sc);
		sx_xunlock(&geneve_sx);
		return;
	}

	sc->gnv_flags |= GENEVE_FLAG_TEARDOWN;
	geneve_teardown_locked(sc);
	sx_xunlock(&geneve_sx);
}

static void
geneve_ifdetach(struct geneve_softc *sc, struct ifnet *ifp,
    struct geneve_softc_head *list)
{

	GENEVE_WLOCK(sc);

	if (sc->gnv_mc_ifp != ifp)
		goto out;
	if (sc->gnv_flags & GENEVE_FLAG_TEARDOWN)
		goto out;

	sc->gnv_flags |= GENEVE_FLAG_TEARDOWN;
	LIST_INSERT_HEAD(list, sc, gnv_ifdetach_list);

out:
	GENEVE_WUNLOCK(sc);
}

static void
geneve_timer(void *xsc)
{
	struct geneve_softc *sc;

	sc = xsc;
	GENEVE_LOCK_WASSERT(sc);

	geneve_ftable_expire(sc);
	callout_schedule(&sc->gnv_callout, geneve_ftable_prune_period * hz);
}

static int
geneve_ioctl_ifflags(struct geneve_softc *sc)
{
	struct ifnet *ifp;

	ifp = sc->gnv_ifp;

	if (ifp->if_flags & IFF_UP) {
		if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
			geneve_init(sc);
	} else {
		if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			geneve_teardown(sc);
	}

	return (0);
}

static int
geneve_ctrl_get_config(struct geneve_softc *sc, void *arg)
{
	struct rm_priotracker tracker;
	struct ifgenevecfg *cfg;

	cfg = arg;
	bzero(cfg, sizeof(*cfg));

	GENEVE_RLOCK(sc, &tracker);
	cfg->gnvc_vni = sc->gnv_vni;
	cfg->gnvc_aws_eni_id = sc->gnv_aws_eni_id;
	memcpy(&cfg->gnvc_local_sa, &sc->gnv_src_addr,
	    sizeof(union geneve_sockaddr));
	memcpy(&cfg->gnvc_remote_sa, &sc->gnv_dst_addr,
	    sizeof(union geneve_sockaddr));
	cfg->gnvc_mc_ifindex = sc->gnv_mc_ifindex;
	cfg->gnvc_ftable_cnt = sc->gnv_ftable_cnt;
	cfg->gnvc_ftable_max = sc->gnv_ftable_max;
	cfg->gnvc_ftable_timeout = sc->gnv_ftable_timeout;
	cfg->gnvc_port_min = sc->gnv_min_port;
	cfg->gnvc_port_max = sc->gnv_max_port;
	cfg->gnvc_learn = (sc->gnv_flags & GENEVE_FLAG_LEARN) != 0;
	cfg->gnvc_ether = (sc->gnv_flags & GENEVE_FLAG_ETHER) != 0;
	cfg->gnvc_ttl = sc->gnv_ttl;
	GENEVE_RUNLOCK(sc, &tracker);

#ifdef INET6
	if (GENEVE_SOCKADDR_IS_IPV6(&cfg->gnvc_local_sa))
		sa6_recoverscope(&cfg->gnvc_local_sa.in6);
	if (GENEVE_SOCKADDR_IS_IPV6(&cfg->gnvc_remote_sa))
		sa6_recoverscope(&cfg->gnvc_remote_sa.in6);
#endif

	return (0);
}

static int
geneve_ctrl_set_vni(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	if (geneve_check_vni(cmd->gnvcmd_vni) != 0)
		return (EINVAL);

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		sc->gnv_vni = cmd->gnvcmd_vni;
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_aws_eni_id(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		sc->gnv_aws_eni_id = cmd->gnvcmd_aws_eni_id;
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_local_addr(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	union geneve_sockaddr *gnvsa;
	int error;

	cmd = arg;
	gnvsa = &cmd->gnvcmd_sa;

	if (!GENEVE_SOCKADDR_IS_IPV46(gnvsa))
		return (EINVAL);
	if (geneve_sockaddr_in_multicast(gnvsa) != 0)
		return (EINVAL);
	if (GENEVE_SOCKADDR_IS_IPV6(gnvsa)) {
		error = geneve_sockaddr_in6_embedscope(gnvsa);
		if (error)
			return (error);
	}

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		geneve_sockaddr_in_copy(&sc->gnv_src_addr, &gnvsa->sa);
		geneve_set_hwcaps(sc);
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_remote_addr(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	union geneve_sockaddr *gnvsa;
	int error;

	cmd = arg;
	gnvsa = &cmd->gnvcmd_sa;

	if (!GENEVE_SOCKADDR_IS_IPV46(gnvsa))
		return (EINVAL);
	if (GENEVE_SOCKADDR_IS_IPV6(gnvsa)) {
		error = geneve_sockaddr_in6_embedscope(gnvsa);
		if (error)
			return (error);
	}

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		geneve_sockaddr_in_copy(&sc->gnv_dst_addr, &gnvsa->sa);
		geneve_setup_interface_hdrlen(sc);
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_local_port(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	if (cmd->gnvcmd_port == 0)
		return (EINVAL);

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		sc->gnv_src_addr.in4.sin_port = htons(cmd->gnvcmd_port);
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_remote_port(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	if (cmd->gnvcmd_port == 0)
		return (EINVAL);

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		sc->gnv_dst_addr.in4.sin_port = htons(cmd->gnvcmd_port);
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_port_range(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	uint16_t min, max;
	int error;

	cmd = arg;
	min = cmd->gnvcmd_port_min;
	max = cmd->gnvcmd_port_max;

	if (max < min)
		return (EINVAL);

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		sc->gnv_min_port = min;
		sc->gnv_max_port = max;
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_ftable_timeout(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (geneve_check_ftable_timeout(cmd->gnvcmd_ftable_timeout) == 0) {
		sc->gnv_ftable_timeout = cmd->gnvcmd_ftable_timeout;
		error = 0;
	} else
		error = EINVAL;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_ftable_max(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (geneve_check_ftable_max(cmd->gnvcmd_ftable_max) == 0) {
		sc->gnv_ftable_max = cmd->gnvcmd_ftable_max;
		error = 0;
	} else
		error = EINVAL;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_multicast_if(struct geneve_softc * sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (geneve_can_change_config(sc)) {
		strlcpy(sc->gnv_mc_ifname, cmd->gnvcmd_ifname, IFNAMSIZ);
		geneve_set_hwcaps(sc);
		error = 0;
	} else
		error = EBUSY;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_ttl(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (geneve_check_ttl(cmd->gnvcmd_ttl) == 0) {
		sc->gnv_ttl = cmd->gnvcmd_ttl;
		if (sc->gnv_im4o != NULL)
			sc->gnv_im4o->imo_multicast_ttl = sc->gnv_ttl;
		if (sc->gnv_im6o != NULL)
			sc->gnv_im6o->im6o_multicast_hlim = sc->gnv_ttl;
		error = 0;
	} else
		error = EINVAL;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_set_learn(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (cmd->gnvcmd_flags & GENEVE_CMD_FLAG_LEARN)
		sc->gnv_flags |= GENEVE_FLAG_LEARN;
	else
		sc->gnv_flags &= ~GENEVE_FLAG_LEARN;
	GENEVE_WUNLOCK(sc);

	return (0);
}

static int
geneve_ctrl_set_ether(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;

	cmd = arg;

	GENEVE_WLOCK(sc);
	if (cmd->gnvcmd_flags & GENEVE_CMD_FLAG_ETHER)
		sc->gnv_flags |= GENEVE_FLAG_ETHER;
	else
		sc->gnv_flags &= ~GENEVE_FLAG_ETHER;
	GENEVE_WUNLOCK(sc);

	return (0);
}

static int
geneve_ctrl_ftable_entry_add(struct geneve_softc *sc, void *arg)
{
	union geneve_sockaddr gnvsa;
	struct ifgenevecmd *cmd;
	struct geneve_ftable_entry *fe;
	int error;

	cmd = arg;
	gnvsa = cmd->gnvcmd_sa;

	if (!GENEVE_SOCKADDR_IS_IPV46(&gnvsa))
		return (EINVAL);
	if (geneve_sockaddr_in_any(&gnvsa) != 0)
		return (EINVAL);
	if (geneve_sockaddr_in_multicast(&gnvsa) != 0)
		return (EINVAL);
	/* BMV: We could support both IPv4 and IPv6 later. */
	if (gnvsa.sa.sa_family != sc->gnv_dst_addr.sa.sa_family)
		return (EAFNOSUPPORT);

	if (GENEVE_SOCKADDR_IS_IPV6(&gnvsa)) {
		error = geneve_sockaddr_in6_embedscope(&gnvsa);
		if (error)
			return (error);
	}

	fe = geneve_ftable_entry_alloc();
	if (fe == NULL)
		return (ENOMEM);

	if (gnvsa.in4.sin_port == 0)
		gnvsa.in4.sin_port = sc->gnv_dst_addr.in4.sin_port;

	geneve_ftable_entry_init(sc, fe, cmd->gnvcmd_mac, &gnvsa.sa,
	    GENEVE_FE_FLAG_STATIC);

	GENEVE_WLOCK(sc);
	error = geneve_ftable_entry_insert(sc, fe);
	GENEVE_WUNLOCK(sc);

	if (error)
		geneve_ftable_entry_free(fe);

	return (error);
}

static int
geneve_ctrl_ftable_entry_rem(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	struct geneve_ftable_entry *fe;
	int error;

	cmd = arg;

	GENEVE_WLOCK(sc);
	fe = geneve_ftable_entry_lookup(sc, cmd->gnvcmd_mac);
	if (fe != NULL) {
		geneve_ftable_entry_destroy(sc, fe);
		error = 0;
	} else
		error = ENOENT;
	GENEVE_WUNLOCK(sc);

	return (error);
}

static int
geneve_ctrl_flush(struct geneve_softc *sc, void *arg)
{
	struct ifgenevecmd *cmd;
	int all;

	cmd = arg;
	all = cmd->gnvcmd_flags & GENEVE_CMD_FLAG_FLUSH_ALL;

	GENEVE_WLOCK(sc);
	geneve_ftable_flush(sc, all);
	GENEVE_WUNLOCK(sc);

	return (0);
}

static int
geneve_ioctl_drvspec(struct geneve_softc *sc, struct ifdrv *ifd, int get)
{
	const struct geneve_control *vc;
	union {
		struct ifgenevecfg	cfg;
		struct ifgenevecmd	cmd;
	} args;
	int out, error;

	if (ifd->ifd_cmd >= geneve_control_table_size)
		return (EINVAL);

	bzero(&args, sizeof(args));
	vc = &geneve_control_table[ifd->ifd_cmd];
	out = (vc->gnvc_flags & GENEVE_CTRL_FLAG_COPYOUT) != 0;

	if ((get != 0 && out == 0) || (get == 0 && out != 0))
		return (EINVAL);

	if (vc->gnvc_flags & GENEVE_CTRL_FLAG_SUSER) {
		error = priv_check(curthread, PRIV_NET_GENEVE);
		if (error)
			return (error);
	}

	if (ifd->ifd_len != vc->gnvc_argsize ||
	    ifd->ifd_len > sizeof(args))
		return (EINVAL);

	if (vc->gnvc_flags & GENEVE_CTRL_FLAG_COPYIN) {
		error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
		if (error)
			return (error);
	}

	error = vc->gnvc_func(sc, &args);
	if (error)
		return (error);

	if (vc->gnvc_flags & GENEVE_CTRL_FLAG_COPYOUT) {
		error = copyout(&args, ifd->ifd_data, ifd->ifd_len);
		if (error)
			return (error);
	}

	return (0);
}

static int
geneve_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct geneve_softc *sc;
	struct ifreq *ifr;
	struct ifdrv *ifd;
	int error;

	sc = ifp->if_softc;
	ifr = (struct ifreq *) data;
	ifd = (struct ifdrv *) data;

	error = 0;

	switch (cmd) {
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

	case SIOCGDRVSPEC:
	case SIOCSDRVSPEC:
		error = geneve_ioctl_drvspec(sc, ifd, cmd == SIOCGDRVSPEC);
		break;

	case SIOCSIFFLAGS:
		error = geneve_ioctl_ifflags(sc);
		break;

	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->gnv_media, cmd);
		break;

	case SIOCSIFMTU:
		if (ifr->ifr_mtu < ETHERMIN || ifr->ifr_mtu > GENEVE_MAX_MTU)
			error = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;

	case SIOCSIFCAP:
		GENEVE_WLOCK(sc);
		error = geneve_set_reqcap(sc, ifp, ifr->ifr_reqcap);
		if (error == 0)
			geneve_set_hwcaps(sc);
		GENEVE_WUNLOCK(sc);
		break;

	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

#if defined(INET) || defined(INET6)
static uint16_t
geneve_pick_source_port(struct geneve_softc *sc, struct mbuf *m)
{
	int range;
	uint32_t hash;

	range = sc->gnv_max_port - sc->gnv_min_port + 1;

	if (M_HASHTYPE_ISHASH(m))
		hash = m->m_pkthdr.flowid;
	else
		hash = jenkins_hash(m->m_data, ETHER_HDR_LEN,
		    sc->gnv_port_hash_key);

	return (sc->gnv_min_port + (hash % range));
}

static void
geneve_encap_header(struct geneve_softc *sc, struct mbuf *m, int ipoff,
    uint16_t srcport, uint16_t dstport, uint16_t ul_type)
{
	struct geneveudphdr *hdr;
	struct udphdr *udph;
	struct geneve_header *gnvh;
	int len;
	uint32_t *cookie_p;
	uint64_t *aws_eni_id_p;
	struct geneve_opthdr *gnvo;

	len = m->m_pkthdr.len - ipoff;
	MPASS(len >= sizeof(struct geneveudphdr));
	hdr = mtodo(m, ipoff);

	udph = &hdr->gnvh_udp;
	udph->uh_sport = srcport;
	udph->uh_dport = dstport;
	udph->uh_ulen = htons(len);
	udph->uh_sum = 0;

	gnvh = &hdr->gnvh_hdr;
	gnvh->gnvh_ver = 0;
	gnvh->gnvh_flags = GENEVE_HDR_FLAGS_CRITICAL;
	gnvh->gnvh_proto = htons(ul_type);
	gnvh->gnvh_vni = htonl(sc->gnv_vni << GENEVE_HDR_VNI_SHIFT);

	gnvo = (struct geneve_opthdr *)(hdr + 1);
	if (sc->gnv_aws_eni_id != 0) {
		gnvo->gnvo_class = htons(0x0108);
		gnvo->gnvo_type = 1;
		gnvo->gnvo_length = 2;
		aws_eni_id_p = (uint64_t *)(gnvo + 1);
		*aws_eni_id_p = htonl(sc->gnv_aws_eni_id);
		gnvo += 3;

		gnvo->gnvo_class = htons(0x0108);
		gnvo->gnvo_type = 2;
		gnvo->gnvo_length = 1;
		cookie_p = (uint32_t *)(gnvo + 1);
		*cookie_p = htonl(m->m_pkthdr.flowid);

		gnvh->gnvh_optlen = 5;
	} else {
		gnvh->gnvh_optlen = 0;
	}

}
#endif

/*
 * Return the CSUM_INNER_* equivalent of CSUM_* caps.
 */
static uint32_t
csum_flags_to_inner_flags(uint32_t csum_flags_in, const uint32_t encap)
{
	uint32_t csum_flags = encap;
	const uint32_t v4 = CSUM_IP | CSUM_IP_UDP | CSUM_IP_TCP;

	/*
	 * csum_flags can request either v4 or v6 offload but not both.
	 * tcp_output always sets CSUM_TSO (both CSUM_IP_TSO and CSUM_IP6_TSO)
	 * so those bits are no good to detect the IP version.  Other bits are
	 * always set with CSUM_TSO and we use those to figure out the IP
	 * version.
	 */
	if (csum_flags_in & v4) {
		if (csum_flags_in & CSUM_IP)
			csum_flags |= CSUM_INNER_IP;
		if (csum_flags_in & CSUM_IP_UDP)
			csum_flags |= CSUM_INNER_IP_UDP;
		if (csum_flags_in & CSUM_IP_TCP)
			csum_flags |= CSUM_INNER_IP_TCP;
		if (csum_flags_in & CSUM_IP_TSO)
			csum_flags |= CSUM_INNER_IP_TSO;
	} else {
#ifdef INVARIANTS
		const uint32_t v6 = CSUM_IP6_UDP | CSUM_IP6_TCP;

		MPASS((csum_flags_in & v6) != 0);
#endif
		if (csum_flags_in & CSUM_IP6_UDP)
			csum_flags |= CSUM_INNER_IP6_UDP;
		if (csum_flags_in & CSUM_IP6_TCP)
			csum_flags |= CSUM_INNER_IP6_TCP;
		if (csum_flags_in & CSUM_IP6_TSO)
			csum_flags |= CSUM_INNER_IP6_TSO;
	}

	return (csum_flags);
}

static int
geneve_encap4(struct geneve_softc *sc, const union geneve_sockaddr *fgnvsa,
    struct mbuf *m, uint16_t ul_type)
{
#ifdef INET
	struct ifnet *ifp;
	struct ip *ip;
	struct in_addr srcaddr, dstaddr;
	uint16_t srcport, dstport;
	int len, mcast, error;
	struct route route, *ro;
	struct sockaddr_in *sin;
	uint32_t csum_flags;
	int optlen;

	NET_EPOCH_ASSERT();

	ifp = sc->gnv_ifp;
	srcaddr = sc->gnv_src_addr.in4.sin_addr;
	srcport = geneve_pick_source_port(sc, m);
	dstaddr = fgnvsa->in4.sin_addr;
	dstport = fgnvsa->in4.sin_port;

	if (sc->gnv_aws_eni_id != 0) {
		optlen = 20;
	} else {
		optlen = 0;
	}

	M_PREPEND(m, sizeof(struct ip) + sizeof(struct geneveudphdr) + optlen,
	    M_NOWAIT);
	if (m == NULL) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENOBUFS);
	}

	len = m->m_pkthdr.len;

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = htons(len);
	ip->ip_off = 0;
	ip->ip_ttl = sc->gnv_ttl;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0;
	ip->ip_src = srcaddr;
	ip->ip_dst = dstaddr;

	geneve_encap_header(sc, m, sizeof(struct ip), srcport, dstport, ul_type);

	mcast = (m->m_flags & (M_MCAST | M_BCAST)) ? 1 : 0;
	m->m_flags &= ~(M_MCAST | M_BCAST);

	m->m_pkthdr.csum_flags &= CSUM_FLAGS_TX;
	if (m->m_pkthdr.csum_flags != 0) {
		/*
		 * HW checksum (L3 and/or L4) or TSO has been requested.  Look
		 * up the ifnet for the outbound route and verify that the
		 * outbound ifnet can perform the requested operation on the
		 * inner frame.
		 */
		bzero(&route, sizeof(route));
		ro = &route;
		sin = (struct sockaddr_in *)&ro->ro_dst;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = ip->ip_dst;
		ro->ro_nh = fib4_lookup(RT_DEFAULT_FIB, ip->ip_dst, 0, NHR_NONE,
		    0);
		if (ro->ro_nh == NULL) {
			m_freem(m);
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (EHOSTUNREACH);
		}

		csum_flags = csum_flags_to_inner_flags(m->m_pkthdr.csum_flags,
		    CSUM_ENCAP_GENEVE);
		if ((csum_flags & ro->ro_nh->nh_ifp->if_hwassist) !=
		    csum_flags) {
			if (ppsratecheck(&sc->err_time, &sc->err_pps, 1)) {
				const struct ifnet *nh_ifp = ro->ro_nh->nh_ifp;

				if_printf(ifp, "interface %s is missing hwcaps "
				    "0x%08x, csum_flags 0x%08x -> 0x%08x, "
				    "hwassist 0x%08x\n", nh_ifp->if_xname,
				    csum_flags & ~(uint32_t)nh_ifp->if_hwassist,
				    m->m_pkthdr.csum_flags, csum_flags,
				    (uint32_t)nh_ifp->if_hwassist);
			}
			m_freem(m);
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (ENXIO);
		}
		m->m_pkthdr.csum_flags = csum_flags;
		if (csum_flags &
		    (CSUM_INNER_IP | CSUM_INNER_IP_UDP | CSUM_INNER_IP6_UDP |
		    CSUM_INNER_IP_TCP | CSUM_INNER_IP6_TCP)) {
			counter_u64_add(sc->gnv_stats.txcsum, 1);
			if (csum_flags & CSUM_INNER_TSO)
				counter_u64_add(sc->gnv_stats.tso, 1);
		}
	} else {
		struct udphdr *hdr = mtodo(m, sizeof(struct ip));

		hdr->uh_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    htons((u_short)len + IPPROTO_UDP));
		m->m_pkthdr.csum_flags = CSUM_IP_UDP;
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
		ro = NULL;
	}
	error = ip_output(m, NULL, ro, 0, sc->gnv_im4o, NULL);
	if (error == 0) {
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
		if (mcast != 0)
			if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);
	} else
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);

	return (error);
#else
	m_freem(m);
	return (ENOTSUP);
#endif
}

static int
geneve_encap6(struct geneve_softc *sc, const union geneve_sockaddr *fgnvsa,
    struct mbuf *m, uint16_t ul_type)
{
#ifdef INET6
	struct ifnet *ifp;
	struct ip6_hdr *ip6;
	const struct in6_addr *srcaddr, *dstaddr;
	uint16_t srcport, dstport;
	int len, mcast, error;
	struct route_in6 route, *ro;
	struct sockaddr_in6 *sin6;
	uint32_t csum_flags;
	int optlen;

	NET_EPOCH_ASSERT();

	ifp = sc->gnv_ifp;
	srcaddr = &sc->gnv_src_addr.in6.sin6_addr;
	srcport = geneve_pick_source_port(sc, m);
	dstaddr = &fgnvsa->in6.sin6_addr;
	dstport = fgnvsa->in6.sin6_port;

	if (sc->gnv_aws_eni_id != 0) {
		optlen = 20;
	} else {
		optlen = 0;
	}

	M_PREPEND(m, sizeof(struct ip6_hdr) + sizeof(struct geneveudphdr) + optlen,
	    M_NOWAIT);
	if (m == NULL) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENOBUFS);
	}

	len = m->m_pkthdr.len;

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;		/* BMV: Keep in forwarding entry? */
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = 0;
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hlim = sc->gnv_ttl;
	ip6->ip6_src = *srcaddr;
	ip6->ip6_dst = *dstaddr;

	geneve_encap_header(sc, m, sizeof(struct ip6_hdr), srcport, dstport, ul_type);

	mcast = (m->m_flags & (M_MCAST | M_BCAST)) ? 1 : 0;
	m->m_flags &= ~(M_MCAST | M_BCAST);

	ro = NULL;
	m->m_pkthdr.csum_flags &= CSUM_FLAGS_TX;
	if (m->m_pkthdr.csum_flags != 0) {
		/*
		 * HW checksum (L3 and/or L4) or TSO has been requested.  Look
		 * up the ifnet for the outbound route and verify that the
		 * outbound ifnet can perform the requested operation on the
		 * inner frame.
		 */
		bzero(&route, sizeof(route));
		ro = &route;
		sin6 = (struct sockaddr_in6 *)&ro->ro_dst;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_addr = ip6->ip6_dst;
		ro->ro_nh = fib6_lookup(RT_DEFAULT_FIB, &ip6->ip6_dst, 0,
		    NHR_NONE, 0);
		if (ro->ro_nh == NULL) {
			m_freem(m);
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (EHOSTUNREACH);
		}

		csum_flags = csum_flags_to_inner_flags(m->m_pkthdr.csum_flags,
		    CSUM_ENCAP_GENEVE);
		if ((csum_flags & ro->ro_nh->nh_ifp->if_hwassist) !=
		    csum_flags) {
			if (ppsratecheck(&sc->err_time, &sc->err_pps, 1)) {
				const struct ifnet *nh_ifp = ro->ro_nh->nh_ifp;

				if_printf(ifp, "interface %s is missing hwcaps "
				    "0x%08x, csum_flags 0x%08x -> 0x%08x, "
				    "hwassist 0x%08x\n", nh_ifp->if_xname,
				    csum_flags & ~(uint32_t)nh_ifp->if_hwassist,
				    m->m_pkthdr.csum_flags, csum_flags,
				    (uint32_t)nh_ifp->if_hwassist);
			}
			m_freem(m);
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
			return (ENXIO);
		}
		m->m_pkthdr.csum_flags = csum_flags;
		if (csum_flags &
		    (CSUM_INNER_IP | CSUM_INNER_IP_UDP | CSUM_INNER_IP6_UDP |
		    CSUM_INNER_IP_TCP | CSUM_INNER_IP6_TCP)) {
			counter_u64_add(sc->gnv_stats.txcsum, 1);
			if (csum_flags & CSUM_INNER_TSO)
				counter_u64_add(sc->gnv_stats.tso, 1);
		}
	} else if (ntohs(dstport) != V_zero_checksum_port) {
		struct udphdr *hdr = mtodo(m, sizeof(struct ip6_hdr));

		hdr->uh_sum = in6_cksum_pseudo(ip6,
		    m->m_pkthdr.len - sizeof(struct ip6_hdr), IPPROTO_UDP, 0);
		m->m_pkthdr.csum_flags = CSUM_UDP_IPV6;
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
	}
	error = ip6_output(m, NULL, ro, 0, sc->gnv_im6o, NULL, NULL);
	if (error == 0) {
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
		if (mcast != 0)
			if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);
	} else
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);

	return (error);
#else
	m_freem(m);
	return (ENOTSUP);
#endif
}

static int
geneve_output(struct ifnet *ifp, struct mbuf *m,
    const struct sockaddr *dst, struct route *ro)
{
	struct geneve_softc *sc;
	struct geneve_ftable_entry *fe;
	union geneve_sockaddr gnvsa;
	int ipv4, error;
	uint16_t ul_type = ETHERTYPE_TRANSETHER;

	sc = ifp->if_softc;
	fe = &sc->gnv_default_fe;

	if (sc->gnv_flags & GENEVE_FLAG_ETHER) {
		return ether_output(ifp, m, dst, ro);
	}
#ifdef INET
	if (dst->sa_family == AF_INET) {
		ul_type = ETHERTYPE_IP;
	}
#endif
#ifdef INET6
	if (dst->sa_family == AF_INET6) {
		ul_type = ETHERTYPE_IPV6;
	}
#endif

	geneve_sockaddr_copy(&gnvsa, &fe->gnvfe_raddr.sa);
	ipv4 = GENEVE_SOCKADDR_IS_IPV4(&gnvsa) != 0;
	if (ipv4) {
		error = geneve_encap4(sc, &gnvsa, m, ul_type);
	} else {
		error = geneve_encap6(sc, &gnvsa, m, ul_type);
	}

	geneve_release(sc);

	return error;
}

static int
geneve_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct rm_priotracker tracker;
	union geneve_sockaddr gnvsa;
	struct geneve_softc *sc;
	struct geneve_ftable_entry *fe;
	struct ifnet *mcifp;
	struct ether_header *eh;
	int ipv4, error;

	sc = ifp->if_softc;
	eh = mtod(m, struct ether_header *);
	fe = NULL;
	mcifp = NULL;

	ETHER_BPF_MTAP(ifp, m);

	GENEVE_RLOCK(sc, &tracker);
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		GENEVE_RUNLOCK(sc, &tracker);
		m_freem(m);
		return (ENETDOWN);
	}

	if ((m->m_flags & (M_BCAST | M_MCAST)) == 0)
		fe = geneve_ftable_entry_lookup(sc, eh->ether_dhost);
	if (fe == NULL)
		fe = &sc->gnv_default_fe;
	geneve_sockaddr_copy(&gnvsa, &fe->gnvfe_raddr.sa);

	ipv4 = GENEVE_SOCKADDR_IS_IPV4(&gnvsa) != 0;
	if (geneve_sockaddr_in_multicast(&gnvsa) != 0)
		mcifp = geneve_multicast_if_ref(sc, ipv4);

	GENEVE_ACQUIRE(sc);
	GENEVE_RUNLOCK(sc, &tracker);

	if (ipv4 != 0)
		error = geneve_encap4(sc, &gnvsa, m, ETHERTYPE_TRANSETHER);
	else
		error = geneve_encap6(sc, &gnvsa, m, ETHERTYPE_TRANSETHER);

	geneve_release(sc);
	if (mcifp != NULL)
		if_rele(mcifp);

	return (error);
}

static void
geneve_qflush(struct ifnet *ifp __unused)
{
}

static void
geneve_parse_opts(struct mbuf *m, int offset, int optlen, uint64_t *aws_eni_id, uint32_t *cookie)
{
	uint8_t opt[260];
	struct geneve_opthdr *gnvoh;
	uint8_t *optp;
	uint64_t *aws_eni_id_p;
	uint32_t *cookie_p;

	if (__predict_false(m->m_len < offset + optlen)) {
		m_copydata(m, offset, optlen, (caddr_t) opt);
		optp = opt;
	} else {
		optp = mtodo(m, offset);
	}

	while (optlen > 0) {
		gnvoh = (struct geneve_opthdr *)optp;
		if (gnvoh->gnvo_class == htons(0x0108)) { /* AWS */
			switch (gnvoh->gnvo_type) {
			case 1: /* 64-bit GWLBE ENI ID */
				aws_eni_id_p = (uint64_t *)(optp + sizeof(struct geneve_opthdr));
				if (aws_eni_id) {
					*aws_eni_id = ntohl(*aws_eni_id_p);
				}
				break;
			case 2: /* 64-bit Customer Visible Attachment ID */
				break;
			case 3: /* 32-bit Flow Cookie */
				cookie_p = (uint32_t *)(optp + sizeof(struct geneve_opthdr));
				if (cookie) {
					*cookie = ntohl(*cookie_p);
				}
				break;
			default:
				break;
			}
		}
		optp += gnvoh->gnvo_length + 1;
		optlen -= gnvoh->gnvo_length + 1;
	}
}

static void
geneve_rcv_udp_packet(struct mbuf *m, int offset, struct inpcb *inpcb,
    const struct sockaddr *srcsa, void *xvso)
{
	struct geneve_socket *vso;
	struct geneve_header *vxh, genevehdr;
	uint32_t vni;
	int error __unused;
	uint64_t aws_eni_id;
	uint16_t ul_type;

	M_ASSERTPKTHDR(m);
	vso = xvso;
	offset += sizeof(struct udphdr);

	if (m->m_pkthdr.len < offset + sizeof(struct geneve_header))
		goto out;

	if (__predict_false(m->m_len < offset + sizeof(struct geneve_header))) {
		m_copydata(m, offset, sizeof(struct geneve_header),
		    (caddr_t) &genevehdr);
		vxh = &genevehdr;
	} else
		vxh = mtodo(m, offset);

	vni = ntohl(vxh->gnvh_vni) >> GENEVE_HDR_VNI_SHIFT;
	ul_type = ntohs(vxh->gnvh_proto);
	if (vxh->gnvh_optlen > 0) {
		geneve_parse_opts(m, offset + sizeof(struct geneve_header),
		    vxh->gnvh_optlen, &aws_eni_id, &m->m_pkthdr.flowid);
	} else {
		aws_eni_id = 0;
	}

	/* Adjust to the start of the inner packet. */
	m_adj(m, offset + sizeof(struct geneve_header) + (vxh->gnvh_optlen << 2));

	error = geneve_input(vso, vni, aws_eni_id, ul_type, &m, srcsa);
	MPASS(error != 0 || m == NULL);

out:
	if (m != NULL)
		m_freem(m);
}

static int
geneve_input(struct geneve_socket *vso, uint32_t vni, uint64_t aws_eni_id,
    uint16_t ul_type, struct mbuf **m0, const struct sockaddr *sa)
{
	struct geneve_softc *sc;
	struct ifnet *ifp;
	struct mbuf *m;
	struct ether_header *eh;
	int error;
	int isr;

	sc = geneve_socket_lookup_softc(vso, vni, aws_eni_id);
	if (sc == NULL)
		return (ENOENT);

	ifp = sc->gnv_ifp;
	m = *m0;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		error = ENETDOWN;
		goto out;
	} else if (ifp == m->m_pkthdr.rcvif) {
		/* XXX Does not catch more complex loops. */
		error = EDEADLK;
		goto out;
	}

	m_clrprotoflags(m);
	m->m_pkthdr.rcvif = ifp;
	M_SETFIB(m, ifp->if_fib);
	if (((ifp->if_capenable & IFCAP_RXCSUM &&
	    m->m_pkthdr.csum_flags & CSUM_INNER_L3_CALC) ||
	    (ifp->if_capenable & IFCAP_RXCSUM_IPV6 &&
	    !(m->m_pkthdr.csum_flags & CSUM_INNER_L3_CALC)))) {
		uint32_t csum_flags = 0;

		if (m->m_pkthdr.csum_flags & CSUM_INNER_L3_CALC)
			csum_flags |= CSUM_L3_CALC;
		if (m->m_pkthdr.csum_flags & CSUM_INNER_L3_VALID)
			csum_flags |= CSUM_L3_VALID;
		if (m->m_pkthdr.csum_flags & CSUM_INNER_L4_CALC)
			csum_flags |= CSUM_L4_CALC;
		if (m->m_pkthdr.csum_flags & CSUM_INNER_L4_VALID)
			csum_flags |= CSUM_L4_VALID;
		m->m_pkthdr.csum_flags = csum_flags;
		counter_u64_add(sc->gnv_stats.rxcsum, 1);
	} else {
		/* clear everything */
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
	}

	switch (ul_type) {
	case ETHERTYPE_IP:
		isr = NETISR_IP;
		break;
	case ETHERTYPE_IPV6:
		isr = NETISR_IPV6;
		break;
	case ETHERTYPE_TRANSETHER:
		if (sc->gnv_flags & GENEVE_FLAG_LEARN) {
			eh = mtod(m, struct ether_header *);
			geneve_ftable_learn(sc, sa, eh->ether_shost);
		}
		isr = NETISR_ETHER;
		break;
	default:
		isr = NETISR_ETHER;
		break;
	}

	error = netisr_dispatch(isr, m);
	*m0 = NULL;

out:
	geneve_release(sc);
	return (error);
}

static int
geneve_stats_alloc(struct geneve_softc *sc)
{
	struct geneve_statistics *stats = &sc->gnv_stats;

	stats->txcsum = counter_u64_alloc(M_WAITOK);
	if (stats->txcsum == NULL)
		goto failed;

	stats->tso = counter_u64_alloc(M_WAITOK);
	if (stats->tso == NULL)
		goto failed;

	stats->rxcsum = counter_u64_alloc(M_WAITOK);
	if (stats->rxcsum == NULL)
		goto failed;

	return (0);
failed:
	geneve_stats_free(sc);
	return (ENOMEM);
}

static void
geneve_stats_free(struct geneve_softc *sc)
{
	struct geneve_statistics *stats = &sc->gnv_stats;

	if (stats->txcsum != NULL) {
		counter_u64_free(stats->txcsum);
		stats->txcsum = NULL;
	}
	if (stats->tso != NULL) {
		counter_u64_free(stats->tso);
		stats->tso = NULL;
	}
	if (stats->rxcsum != NULL) {
		counter_u64_free(stats->rxcsum);
		stats->rxcsum = NULL;
	}
}

static void
geneve_set_default_config(struct geneve_softc *sc)
{

	sc->gnv_flags |= GENEVE_FLAG_LEARN;
	sc->gnv_flags |= GENEVE_FLAG_ETHER;

	sc->gnv_vni = GENEVE_VNI_MAX;
	sc->gnv_aws_eni_id = 0;
	sc->gnv_ttl = IPDEFTTL;

	sc->gnv_src_addr.in4.sin_port = htons(GENEVE_PORT);
	sc->gnv_dst_addr.in4.sin_port = htons(GENEVE_PORT);

	sc->gnv_min_port = V_ipport_firstauto;
	sc->gnv_max_port = V_ipport_lastauto;

	sc->gnv_ftable_max = GENEVE_FTABLE_MAX;
	sc->gnv_ftable_timeout = GENEVE_FTABLE_TIMEOUT;
}

static int
geneve_set_user_config(struct geneve_softc *sc, struct ifgeneveparam *gnvp)
{

#ifndef INET
	if (gnvp->gnvp_with & (GENEVE_PARAM_WITH_LOCAL_ADDR4 |
	    GENEVE_PARAM_WITH_REMOTE_ADDR4))
		return (EAFNOSUPPORT);
#endif

#ifndef INET6
	if (gnvp->gnvp_with & (GENEVE_PARAM_WITH_LOCAL_ADDR6 |
	    GENEVE_PARAM_WITH_REMOTE_ADDR6))
		return (EAFNOSUPPORT);
#else
	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_LOCAL_ADDR6) {
		int error = geneve_sockaddr_in6_embedscope(&gnvp->gnvp_local_sa);
		if (error)
			return (error);
	}
	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_REMOTE_ADDR6) {
		int error = geneve_sockaddr_in6_embedscope(
		   &gnvp->gnvp_remote_sa);
		if (error)
			return (error);
	}
#endif

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_VNI) {
		if (geneve_check_vni(gnvp->gnvp_vni) == 0)
			sc->gnv_vni = gnvp->gnvp_vni;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_AWS_ENI_ID) {
		sc->gnv_aws_eni_id = gnvp->gnvp_aws_eni_id;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_LOCAL_ADDR4) {
		sc->gnv_src_addr.in4.sin_len = sizeof(struct sockaddr_in);
		sc->gnv_src_addr.in4.sin_family = AF_INET;
		sc->gnv_src_addr.in4.sin_addr =
		    gnvp->gnvp_local_sa.in4.sin_addr;
	} else if (gnvp->gnvp_with & GENEVE_PARAM_WITH_LOCAL_ADDR6) {
		sc->gnv_src_addr.in6.sin6_len = sizeof(struct sockaddr_in6);
		sc->gnv_src_addr.in6.sin6_family = AF_INET6;
		sc->gnv_src_addr.in6.sin6_addr =
		    gnvp->gnvp_local_sa.in6.sin6_addr;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_REMOTE_ADDR4) {
		sc->gnv_dst_addr.in4.sin_len = sizeof(struct sockaddr_in);
		sc->gnv_dst_addr.in4.sin_family = AF_INET;
		sc->gnv_dst_addr.in4.sin_addr =
		    gnvp->gnvp_remote_sa.in4.sin_addr;
	} else if (gnvp->gnvp_with & GENEVE_PARAM_WITH_REMOTE_ADDR6) {
		sc->gnv_dst_addr.in6.sin6_len = sizeof(struct sockaddr_in6);
		sc->gnv_dst_addr.in6.sin6_family = AF_INET6;
		sc->gnv_dst_addr.in6.sin6_addr =
		    gnvp->gnvp_remote_sa.in6.sin6_addr;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_LOCAL_PORT)
		sc->gnv_src_addr.in4.sin_port = htons(gnvp->gnvp_local_port);
	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_REMOTE_PORT)
		sc->gnv_dst_addr.in4.sin_port = htons(gnvp->gnvp_remote_port);

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_PORT_RANGE) {
		if (gnvp->gnvp_min_port <= gnvp->gnvp_max_port) {
			sc->gnv_min_port = gnvp->gnvp_min_port;
			sc->gnv_max_port = gnvp->gnvp_max_port;
		}
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_MULTICAST_IF)
		strlcpy(sc->gnv_mc_ifname, gnvp->gnvp_mc_ifname, IFNAMSIZ);

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_FTABLE_TIMEOUT) {
		if (geneve_check_ftable_timeout(gnvp->gnvp_ftable_timeout) == 0)
			sc->gnv_ftable_timeout = gnvp->gnvp_ftable_timeout;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_FTABLE_MAX) {
		if (geneve_check_ftable_max(gnvp->gnvp_ftable_max) == 0)
			sc->gnv_ftable_max = gnvp->gnvp_ftable_max;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_TTL) {
		if (geneve_check_ttl(gnvp->gnvp_ttl) == 0)
			sc->gnv_ttl = gnvp->gnvp_ttl;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_LEARN) {
		if (gnvp->gnvp_learn == 0)
			sc->gnv_flags &= ~GENEVE_FLAG_LEARN;
	}

	if (gnvp->gnvp_with & GENEVE_PARAM_WITH_ETHER) {
		if (gnvp->gnvp_ether == 0)
			sc->gnv_flags &= ~GENEVE_FLAG_ETHER;
	}

	return (0);
}

static int
geneve_set_reqcap(struct geneve_softc *sc, struct ifnet *ifp, int reqcap)
{
	int mask = reqcap ^ ifp->if_capenable;

	/* Disable TSO if tx checksums are disabled. */
	if (mask & IFCAP_TXCSUM && !(reqcap & IFCAP_TXCSUM) &&
	    reqcap & IFCAP_TSO4) {
		reqcap &= ~IFCAP_TSO4;
		if_printf(ifp, "tso4 disabled due to -txcsum.\n");
	}
	if (mask & IFCAP_TXCSUM_IPV6 && !(reqcap & IFCAP_TXCSUM_IPV6) &&
	    reqcap & IFCAP_TSO6) {
		reqcap &= ~IFCAP_TSO6;
		if_printf(ifp, "tso6 disabled due to -txcsum6.\n");
	}

	/* Do not enable TSO if tx checksums are disabled. */
	if (mask & IFCAP_TSO4 && reqcap & IFCAP_TSO4 &&
	    !(reqcap & IFCAP_TXCSUM)) {
		if_printf(ifp, "enable txcsum first.\n");
		return (EAGAIN);
	}
	if (mask & IFCAP_TSO6 && reqcap & IFCAP_TSO6 &&
	    !(reqcap & IFCAP_TXCSUM_IPV6)) {
		if_printf(ifp, "enable txcsum6 first.\n");
		return (EAGAIN);
	}

	sc->gnv_reqcap = reqcap;
	return (0);
}

/*
 * A GENEVE interface inherits the capabilities of the genevedev or the interface
 * hosting the genevelocal address.
 */
static void
geneve_set_hwcaps(struct geneve_softc *sc)
{
	struct epoch_tracker et;
	struct ifnet *p;
	struct ifaddr *ifa;
	u_long hwa;
	int cap, ena;
	bool rel;
	struct ifnet *ifp = sc->gnv_ifp;

	/* reset caps */
	ifp->if_capabilities &= GENEVE_BASIC_IFCAPS;
	ifp->if_capenable &= GENEVE_BASIC_IFCAPS;
	ifp->if_hwassist = 0;

	NET_EPOCH_ENTER(et);
	CURVNET_SET(ifp->if_vnet);

	rel = false;
	p = NULL;
	if (sc->gnv_mc_ifname[0] != '\0') {
		rel = true;
		p = ifunit_ref(sc->gnv_mc_ifname);
	} else if (geneve_sockaddr_in_any(&sc->gnv_src_addr) == 0) {
		if (sc->gnv_src_addr.sa.sa_family == AF_INET) {
			struct sockaddr_in in4 = sc->gnv_src_addr.in4;

			in4.sin_port = 0;
			ifa = ifa_ifwithaddr((struct sockaddr *)&in4);
			if (ifa != NULL)
				p = ifa->ifa_ifp;
		} else if (sc->gnv_src_addr.sa.sa_family == AF_INET6) {
			struct sockaddr_in6 in6 = sc->gnv_src_addr.in6;

			in6.sin6_port = 0;
			ifa = ifa_ifwithaddr((struct sockaddr *)&in6);
			if (ifa != NULL)
				p = ifa->ifa_ifp;
		}
	}
	if (p == NULL)
		goto done;

	cap = ena = hwa = 0;

	/* checksum offload */
	if (p->if_capabilities & IFCAP_GENEVE_HWCSUM)
		cap |= p->if_capabilities & (IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6);
	if (p->if_capenable & IFCAP_GENEVE_HWCSUM) {
		ena |= sc->gnv_reqcap & p->if_capenable &
		    (IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6);
		if (ena & IFCAP_TXCSUM) {
			if (p->if_hwassist & CSUM_INNER_IP)
				hwa |= CSUM_IP;
			if (p->if_hwassist & CSUM_INNER_IP_UDP)
				hwa |= CSUM_IP_UDP;
			if (p->if_hwassist & CSUM_INNER_IP_TCP)
				hwa |= CSUM_IP_TCP;
		}
		if (ena & IFCAP_TXCSUM_IPV6) {
			if (p->if_hwassist & CSUM_INNER_IP6_UDP)
				hwa |= CSUM_IP6_UDP;
			if (p->if_hwassist & CSUM_INNER_IP6_TCP)
				hwa |= CSUM_IP6_TCP;
		}
	}

	/* hardware TSO */
	if (p->if_capabilities & IFCAP_GENEVE_HWTSO) {
		cap |= p->if_capabilities & IFCAP_TSO;
		if (p->if_hw_tsomax > IP_MAXPACKET - ifp->if_hdrlen)
			ifp->if_hw_tsomax = IP_MAXPACKET - ifp->if_hdrlen;
		else
			ifp->if_hw_tsomax = p->if_hw_tsomax;
		/* XXX: tsomaxsegcount decrement is cxgbe specific  */
		ifp->if_hw_tsomaxsegcount = p->if_hw_tsomaxsegcount - 1;
		ifp->if_hw_tsomaxsegsize = p->if_hw_tsomaxsegsize;
	}
	if (p->if_capenable & IFCAP_GENEVE_HWTSO) {
		ena |= sc->gnv_reqcap & p->if_capenable & IFCAP_TSO;
		if (ena & IFCAP_TSO) {
			if (p->if_hwassist & CSUM_INNER_IP_TSO)
				hwa |= CSUM_IP_TSO;
			if (p->if_hwassist & CSUM_INNER_IP6_TSO)
				hwa |= CSUM_IP6_TSO;
		}
	}

	ifp->if_capabilities |= cap;
	ifp->if_capenable |= ena;
	ifp->if_hwassist |= hwa;
	if (rel)
		if_rele(p);
done:
	CURVNET_RESTORE();
	NET_EPOCH_EXIT(et);
}

static int
geneve_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	struct geneve_softc *sc;
	struct ifnet *ifp;
	struct ifgeneveparam gnvp;
	int error;

	sc = malloc(sizeof(struct geneve_softc), M_GENEVE, M_WAITOK | M_ZERO);
	sc->gnv_unit = unit;
	geneve_set_default_config(sc);
	error = geneve_stats_alloc(sc);
	if (error != 0)
		goto fail;

	if (params != 0) {
		error = copyin(params, &gnvp, sizeof(gnvp));
		if (error)
			goto fail;

		error = geneve_set_user_config(sc, &gnvp);
		if (error)
			goto fail;
	}

	ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		error = ENOSPC;
		goto fail;
	}

	sc->gnv_ifp = ifp;
	rm_init(&sc->gnv_lock, "geneverm");
	callout_init_rw(&sc->gnv_callout, &sc->gnv_lock, 0);
	sc->gnv_port_hash_key = arc4random();
	geneve_ftable_init(sc);

	geneve_sysctl_setup(sc);

	ifp->if_softc = sc;
	if_initname(ifp, geneve_name, unit);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_init = geneve_init;
	ifp->if_ioctl = geneve_ioctl;
	ifp->if_transmit = geneve_transmit;
	ifp->if_qflush = geneve_qflush;
	ifp->if_capabilities = GENEVE_BASIC_IFCAPS;
	ifp->if_capenable = GENEVE_BASIC_IFCAPS;
	sc->gnv_reqcap = -1;
	geneve_set_hwcaps(sc);

	ifmedia_init(&sc->gnv_media, 0, geneve_media_change, geneve_media_status);
	ifmedia_add(&sc->gnv_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->gnv_media, IFM_ETHER | IFM_AUTO);

	ether_gen_addr(ifp, &sc->gnv_hwaddr);
	ether_ifattach(ifp, sc->gnv_hwaddr.octet);

	/* rewrite if_output */
	ifp->if_output = geneve_output;

	ifp->if_baudrate = 0;
	geneve_setup_interface_hdrlen(sc);

	return (0);

fail:
	free(sc, M_GENEVE);
	return (error);
}

static void
geneve_clone_destroy(struct ifnet *ifp)
{
	struct geneve_softc *sc;

	sc = ifp->if_softc;

	geneve_teardown(sc);

	geneve_ftable_flush(sc, 1);

	ether_ifdetach(ifp);
	if_free(ifp);
	ifmedia_removeall(&sc->gnv_media);

	geneve_ftable_fini(sc);

	geneve_sysctl_destroy(sc);
	rm_destroy(&sc->gnv_lock);
	geneve_stats_free(sc);
	free(sc, M_GENEVE);
}

/* BMV: Taken from if_bridge. */
static uint32_t
geneve_mac_hash(struct geneve_softc *sc, const uint8_t *addr)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = sc->gnv_ftable_hash_key;

	b += addr[5] << 8;
	b += addr[4];
	a += addr[3] << 24;
	a += addr[2] << 16;
	a += addr[1] << 8;
	a += addr[0];

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 */
#define	mix(a, b, c)							\
do {									\
	a -= b; a -= c; a ^= (c >> 13);					\
	b -= c; b -= a; b ^= (a << 8);					\
	c -= a; c -= b; c ^= (b >> 13);					\
	a -= b; a -= c; a ^= (c >> 12);					\
	b -= c; b -= a; b ^= (a << 16);					\
	c -= a; c -= b; c ^= (b >> 5);					\
	a -= b; a -= c; a ^= (c >> 3);					\
	b -= c; b -= a; b ^= (a << 10);					\
	c -= a; c -= b; c ^= (b >> 15);					\
} while (0)

	mix(a, b, c);

#undef mix

	return (c);
}

static int
geneve_media_change(struct ifnet *ifp)
{

	/* Ignore. */
	return (0);
}

static void
geneve_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{

	ifmr->ifm_status = IFM_ACTIVE | IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER | IFM_FDX;
}

static int
geneve_sockaddr_cmp(const union geneve_sockaddr *gnvaddr,
    const struct sockaddr *sa)
{

	return (bcmp(&gnvaddr->sa, sa, gnvaddr->sa.sa_len));
}

static void
geneve_sockaddr_copy(union geneve_sockaddr *gnvaddr,
    const struct sockaddr *sa)
{

	MPASS(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);
	bzero(gnvaddr, sizeof(*gnvaddr));

	if (sa->sa_family == AF_INET) {
		gnvaddr->in4 = *satoconstsin(sa);
		gnvaddr->in4.sin_len = sizeof(struct sockaddr_in);
	} else if (sa->sa_family == AF_INET6) {
		gnvaddr->in6 = *satoconstsin6(sa);
		gnvaddr->in6.sin6_len = sizeof(struct sockaddr_in6);
	}
}

static int
geneve_sockaddr_in_equal(const union geneve_sockaddr *gnvaddr,
    const struct sockaddr *sa)
{
	int equal;

	if (sa->sa_family == AF_INET) {
		const struct in_addr *in4 = &satoconstsin(sa)->sin_addr;
		equal = in4->s_addr == gnvaddr->in4.sin_addr.s_addr;
	} else if (sa->sa_family == AF_INET6) {
		const struct in6_addr *in6 = &satoconstsin6(sa)->sin6_addr;
		equal = IN6_ARE_ADDR_EQUAL(in6, &gnvaddr->in6.sin6_addr);
	} else
		equal = 0;

	return (equal);
}

static void
geneve_sockaddr_in_copy(union geneve_sockaddr *gnvaddr,
    const struct sockaddr *sa)
{

	MPASS(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);

	if (sa->sa_family == AF_INET) {
		const struct in_addr *in4 = &satoconstsin(sa)->sin_addr;
		gnvaddr->in4.sin_family = AF_INET;
		gnvaddr->in4.sin_len = sizeof(struct sockaddr_in);
		gnvaddr->in4.sin_addr = *in4;
	} else if (sa->sa_family == AF_INET6) {
		const struct in6_addr *in6 = &satoconstsin6(sa)->sin6_addr;
		gnvaddr->in6.sin6_family = AF_INET6;
		gnvaddr->in6.sin6_len = sizeof(struct sockaddr_in6);
		gnvaddr->in6.sin6_addr = *in6;
	}
}

static int
geneve_sockaddr_supported(const union geneve_sockaddr *gnvaddr, int unspec)
{
	const struct sockaddr *sa;
	int supported;

	sa = &gnvaddr->sa;
	supported = 0;

	if (sa->sa_family == AF_UNSPEC && unspec != 0) {
		supported = 1;
	} else if (sa->sa_family == AF_INET) {
#ifdef INET
		supported = 1;
#endif
	} else if (sa->sa_family == AF_INET6) {
#ifdef INET6
		supported = 1;
#endif
	}

	return (supported);
}

static int
geneve_sockaddr_in_any(const union geneve_sockaddr *gnvaddr)
{
	const struct sockaddr *sa;
	int any;

	sa = &gnvaddr->sa;

	if (sa->sa_family == AF_INET) {
		const struct in_addr *in4 = &satoconstsin(sa)->sin_addr;
		any = in4->s_addr == INADDR_ANY;
	} else if (sa->sa_family == AF_INET6) {
		const struct in6_addr *in6 = &satoconstsin6(sa)->sin6_addr;
		any = IN6_IS_ADDR_UNSPECIFIED(in6);
	} else
		any = -1;

	return (any);
}

static int
geneve_sockaddr_in_multicast(const union geneve_sockaddr *gnvaddr)
{
	const struct sockaddr *sa;
	int mc;

	sa = &gnvaddr->sa;

	if (sa->sa_family == AF_INET) {
		const struct in_addr *in4 = &satoconstsin(sa)->sin_addr;
		mc = IN_MULTICAST(ntohl(in4->s_addr));
	} else if (sa->sa_family == AF_INET6) {
		const struct in6_addr *in6 = &satoconstsin6(sa)->sin6_addr;
		mc = IN6_IS_ADDR_MULTICAST(in6);
	} else
		mc = -1;

	return (mc);
}

static int
geneve_sockaddr_in6_embedscope(union geneve_sockaddr *gnvaddr)
{
	int error;

	MPASS(GENEVE_SOCKADDR_IS_IPV6(gnvaddr));
#ifdef INET6
	error = sa6_embedscope(&gnvaddr->in6, V_ip6_use_defzone);
#else
	error = EAFNOSUPPORT;
#endif

	return (error);
}

static int
geneve_can_change_config(struct geneve_softc *sc)
{
	struct ifnet *ifp;

	ifp = sc->gnv_ifp;
	GENEVE_LOCK_ASSERT(sc);

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		return (0);
	if (sc->gnv_flags & (GENEVE_FLAG_INIT | GENEVE_FLAG_TEARDOWN))
		return (0);

	return (1);
}

static int
geneve_check_vni(uint32_t vni)
{

	return (vni >= GENEVE_VNI_MAX);
}

static int
geneve_check_ttl(int ttl)
{

	return (ttl > MAXTTL);
}

static int
geneve_check_ftable_timeout(uint32_t timeout)
{

	return (timeout > GENEVE_FTABLE_MAX_TIMEOUT);
}

static int
geneve_check_ftable_max(uint32_t max)
{

	return (max > GENEVE_FTABLE_MAX);
}

static void
geneve_sysctl_setup(struct geneve_softc *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *node;
	struct geneve_statistics *stats;
	char namebuf[8];

	ctx = &sc->gnv_sysctl_ctx;
	stats = &sc->gnv_stats;
	snprintf(namebuf, sizeof(namebuf), "%d", sc->gnv_unit);

	sysctl_ctx_init(ctx);
	sc->gnv_sysctl_node = SYSCTL_ADD_NODE(ctx,
	    SYSCTL_STATIC_CHILDREN(_net_link_geneve), OID_AUTO, namebuf,
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "");

	node = SYSCTL_ADD_NODE(ctx, SYSCTL_CHILDREN(sc->gnv_sysctl_node),
	    OID_AUTO, "ftable", CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "count",
	    CTLFLAG_RD, &sc->gnv_ftable_cnt, 0,
	    "Number of entries in fowarding table");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "max",
	     CTLFLAG_RD, &sc->gnv_ftable_max, 0,
	    "Maximum number of entries allowed in fowarding table");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "timeout",
	    CTLFLAG_RD, &sc->gnv_ftable_timeout, 0,
	    "Number of seconds between prunes of the forwarding table");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "dump",
	    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP,
	    sc, 0, geneve_ftable_sysctl_dump, "A",
	    "Dump the forwarding table entries");

	node = SYSCTL_ADD_NODE(ctx, SYSCTL_CHILDREN(sc->gnv_sysctl_node),
	    OID_AUTO, "stats", CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(node), OID_AUTO,
	    "ftable_nospace", CTLFLAG_RD, &stats->ftable_nospace, 0,
	    "Fowarding table reached maximum entries");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(node), OID_AUTO,
	    "ftable_lock_upgrade_failed", CTLFLAG_RD,
	    &stats->ftable_lock_upgrade_failed, 0,
	    "Forwarding table update required lock upgrade");

	SYSCTL_ADD_COUNTER_U64(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "txcsum",
	    CTLFLAG_RD, &stats->txcsum,
	    "# of times hardware assisted with tx checksum");
	SYSCTL_ADD_COUNTER_U64(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "tso",
	    CTLFLAG_RD, &stats->tso, "# of times hardware assisted with TSO");
	SYSCTL_ADD_COUNTER_U64(ctx, SYSCTL_CHILDREN(node), OID_AUTO, "rxcsum",
	    CTLFLAG_RD, &stats->rxcsum,
	    "# of times hardware assisted with rx checksum");
}

static void
geneve_sysctl_destroy(struct geneve_softc *sc)
{

	sysctl_ctx_free(&sc->gnv_sysctl_ctx);
	sc->gnv_sysctl_node = NULL;
}

#if 0
static int
geneve_tunable_int(struct geneve_softc *sc, const char *knob, int def)
{
	char path[64];

	snprintf(path, sizeof(path), "net.link.geneve.%d.%s",
	    sc->gnv_unit, knob);
	TUNABLE_INT_FETCH(path, &def);

	return (def);
}
#endif

static void
geneve_ifdetach_event(void *arg __unused, struct ifnet *ifp)
{
	struct geneve_softc_head list;
	struct geneve_socket *vso;
	struct geneve_softc *sc, *tsc;

	LIST_INIT(&list);

	if (ifp->if_flags & IFF_RENAMING)
		return;
	if ((ifp->if_flags & IFF_MULTICAST) == 0)
		return;

	GENEVE_LIST_LOCK();
	LIST_FOREACH(vso, &geneve_socket_list, gnvso_entry)
		geneve_socket_ifdetach(vso, ifp, &list);
	GENEVE_LIST_UNLOCK();

	LIST_FOREACH_SAFE(sc, &list, gnv_ifdetach_list, tsc) {
		LIST_REMOVE(sc, gnv_ifdetach_list);

		sx_xlock(&geneve_sx);
		GENEVE_WLOCK(sc);
		if (sc->gnv_flags & GENEVE_FLAG_INIT)
			geneve_init_wait(sc);
		geneve_teardown_locked(sc);
		sx_xunlock(&geneve_sx);
	}
}

static void
geneve_load(void)
{

	mtx_init(&geneve_list_mtx, "geneve list", NULL, MTX_DEF);
	LIST_INIT(&geneve_socket_list);
	geneve_ifdetach_event_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    geneve_ifdetach_event, NULL, EVENTHANDLER_PRI_ANY);
	geneve_cloner = if_clone_simple(geneve_name, geneve_clone_create,
	    geneve_clone_destroy, 0);
}

static void
geneve_unload(void)
{

	EVENTHANDLER_DEREGISTER(ifnet_departure_event,
	    geneve_ifdetach_event_tag);
	if_clone_detach(geneve_cloner);
	mtx_destroy(&geneve_list_mtx);
	MPASS(LIST_EMPTY(&geneve_socket_list));
}

static int
geneve_modevent(module_t mod, int type, void *unused)
{
	int error;

	error = 0;

	switch (type) {
	case MOD_LOAD:
		geneve_load();
		break;
	case MOD_UNLOAD:
		geneve_unload();
		break;
	default:
		error = ENOTSUP;
		break;
	}

	return (error);
}

static moduledata_t geneve_mod = {
	"if_geneve",
	geneve_modevent,
	0
};

DECLARE_MODULE(if_geneve, geneve_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_geneve, 1);
