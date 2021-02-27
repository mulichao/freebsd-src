/*-
 * Copyright (c) 2014, Bryan Venteicher <bryanv@FreeBSD.org>
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
 *
 * $FreeBSD$
 */

#ifndef _NET_IF_GENEVE_H_
#define _NET_IF_GENEVE_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

struct geneve_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t  gnvh_optlen:6,
	         gnvh_ver:2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t  gnvh_ver:2,    /* version */
	         gnvh_optlen:6; /* option length */
#endif
	uint8_t  gnvh_flags;
	uint16_t gnvh_proto;
	uint32_t gnvh_vni;
};

#define GENEVE_HDR_FLAGS_CTRL		0x80
#define GENEVE_HDR_FLAGS_CRITICAL	0x40
#define GENEVE_HDR_FLAGS_VALID_VNI	0x08000000
#define GENEVE_HDR_VNI_SHIFT		8

#define GENEVE_VNI_MAX	(1 << 24)
#define GENEVE_VNI_MASK	(GENEVE_VNI_MAX - 1)

#define GENEVE_PORT		6081

union geneve_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	in4;
	struct sockaddr_in6	in6;
};

struct ifgeneveparam {
	uint64_t		gnvp_with;

#define GENEVE_PARAM_WITH_VNI			0x0001
#define GENEVE_PARAM_WITH_LOCAL_ADDR4		0x0002
#define GENEVE_PARAM_WITH_LOCAL_ADDR6		0x0004
#define GENEVE_PARAM_WITH_REMOTE_ADDR4		0x0008
#define GENEVE_PARAM_WITH_REMOTE_ADDR6		0x0010
#define GENEVE_PARAM_WITH_LOCAL_PORT		0x0020
#define GENEVE_PARAM_WITH_REMOTE_PORT		0x0040
#define GENEVE_PARAM_WITH_PORT_RANGE		0x0080
#define GENEVE_PARAM_WITH_FTABLE_TIMEOUT	0x0100
#define GENEVE_PARAM_WITH_FTABLE_MAX		0x0200
#define GENEVE_PARAM_WITH_MULTICAST_IF		0x0400
#define GENEVE_PARAM_WITH_TTL			0x0800
#define GENEVE_PARAM_WITH_LEARN			0x1000
#define GENEVE_PARAM_WITH_AWS_ENI_ID		0x2000
#define GENEVE_PARAM_WITH_ETHER			0x4000

	uint32_t		gnvp_vni;
	union geneve_sockaddr 	gnvp_local_sa;
	union geneve_sockaddr 	gnvp_remote_sa;
	uint16_t		gnvp_local_port;
	uint16_t		gnvp_remote_port;
	uint16_t		gnvp_min_port;
	uint16_t		gnvp_max_port;
	char			gnvp_mc_ifname[IFNAMSIZ];
	uint32_t		gnvp_ftable_timeout;
	uint32_t		gnvp_ftable_max;
	uint8_t			gnvp_ttl;
	uint8_t			gnvp_learn;
	uint64_t		gnvp_aws_eni_id;
	uint8_t			gnvp_ether;
};

#define GENEVE_SOCKADDR_IS_IPV4(_vxsin)	((_vxsin)->sa.sa_family == AF_INET)
#define GENEVE_SOCKADDR_IS_IPV6(_vxsin)	((_vxsin)->sa.sa_family == AF_INET6)
#define GENEVE_SOCKADDR_IS_IPV46(_vxsin) \
    (GENEVE_SOCKADDR_IS_IPV4(_vxsin) || GENEVE_SOCKADDR_IS_IPV6(_vxsin))

#define GENEVE_CMD_GET_CONFIG		0
#define GENEVE_CMD_SET_VNI		1
#define GENEVE_CMD_SET_LOCAL_ADDR	2
#define GENEVE_CMD_SET_REMOTE_ADDR	4
#define GENEVE_CMD_SET_LOCAL_PORT	5
#define GENEVE_CMD_SET_REMOTE_PORT	6
#define GENEVE_CMD_SET_PORT_RANGE	7
#define GENEVE_CMD_SET_FTABLE_TIMEOUT	8
#define GENEVE_CMD_SET_FTABLE_MAX	9
#define GENEVE_CMD_SET_MULTICAST_IF	10
#define GENEVE_CMD_SET_TTL		11
#define GENEVE_CMD_SET_LEARN		12
#define GENEVE_CMD_FTABLE_ENTRY_ADD	13
#define GENEVE_CMD_FTABLE_ENTRY_REM	14
#define GENEVE_CMD_FLUSH			15
#define GENEVE_CMD_SET_AWS_ENI_ID	16
#define GENEVE_CMD_SET_ETHER		17

struct ifgenevecfg {
	uint32_t		gnvc_vni;
	union geneve_sockaddr	gnvc_local_sa;
	union geneve_sockaddr	gnvc_remote_sa;
	uint32_t		gnvc_mc_ifindex;
	uint32_t		gnvc_ftable_cnt;
	uint32_t		gnvc_ftable_max;
	uint32_t		gnvc_ftable_timeout;
	uint16_t		gnvc_port_min;
	uint16_t		gnvc_port_max;
	uint8_t			gnvc_learn;
	uint8_t			gnvc_ttl;
	uint64_t		gnvc_aws_eni_id;
	uint8_t			gnvc_ether;
};

struct ifgenevecmd {
	uint32_t		gnvcmd_flags;
#define GENEVE_CMD_FLAG_FLUSH_ALL	0x0001
#define GENEVE_CMD_FLAG_LEARN		0x0002
#define	GENEVE_CMD_FLAG_ETHER		0x0004

	uint32_t		gnvcmd_vni;
	uint32_t		gnvcmd_ftable_timeout;
	uint32_t		gnvcmd_ftable_max;
	uint16_t		gnvcmd_port;
	uint16_t		gnvcmd_port_min;
	uint16_t		gnvcmd_port_max;
	uint8_t			gnvcmd_mac[ETHER_ADDR_LEN];
	uint8_t			gnvcmd_ttl;
	union geneve_sockaddr	gnvcmd_sa;
	char			gnvcmd_ifname[IFNAMSIZ];
	uint64_t		gnvcmd_aws_eni_id;
};

#ifdef _KERNEL
typedef void (*geneve_event_handler_t)(void *, struct ifnet *, sa_family_t,
    u_int);
EVENTHANDLER_DECLARE(geneve_start, geneve_event_handler_t);
EVENTHANDLER_DECLARE(geneve_stop, geneve_event_handler_t);
#endif

#endif /* _NET_IF_GENEVE_H_ */
