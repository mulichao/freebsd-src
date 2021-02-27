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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_geneve.h>
#include <net/route.h>
#include <netinet/in.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

static struct ifgeneveparam params = {
	.gnvp_vni	= GENEVE_VNI_MAX,
};

static int
get_val(const char *cp, u_long *valp)
{
	char *endptr;
	u_long val;

	errno = 0;
	val = strtoul(cp, &endptr, 0);
	if (cp[0] == '\0' || endptr[0] != '\0' || errno == ERANGE)
		return (-1);

	*valp = val;
	return (0);
}

static int
do_cmd(int sock, u_long op, void *arg, size_t argsize, int set)
{
	struct ifdrv ifd;

	bzero(&ifd, sizeof(ifd));

	strlcpy(ifd.ifd_name, ifr.ifr_name, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;

	return (ioctl(sock, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd));
}

static int
geneve_exists(int sock)
{
	struct ifgenevecfg cfg;

	bzero(&cfg, sizeof(cfg));

	return (do_cmd(sock, GENEVE_CMD_GET_CONFIG, &cfg, sizeof(cfg), 0) != -1);
}

static void
geneve_status(int s)
{
	struct ifgenevecfg cfg;
	char src[NI_MAXHOST], dst[NI_MAXHOST];
	char srcport[NI_MAXSERV], dstport[NI_MAXSERV];
	struct sockaddr *lsa, *rsa;
	int vni, mc, ipv6;
	uint64_t aws_eni_id;
	uint8_t ether;

	bzero(&cfg, sizeof(cfg));

	if (do_cmd(s, GENEVE_CMD_GET_CONFIG, &cfg, sizeof(cfg), 0) < 0)
		return;

	vni = cfg.gnvc_vni;
	aws_eni_id = cfg.gnvc_aws_eni_id;
	ether = cfg.gnvc_ether;
	lsa = &cfg.gnvc_local_sa.sa;
	rsa = &cfg.gnvc_remote_sa.sa;
	ipv6 = rsa->sa_family == AF_INET6;

	/* Just report nothing if the network identity isn't set yet. */
	if (vni >= GENEVE_VNI_MAX)
		return;

	if (getnameinfo(lsa, lsa->sa_len, src, sizeof(src),
	    srcport, sizeof(srcport), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		src[0] = srcport[0] = '\0';
	if (getnameinfo(rsa, rsa->sa_len, dst, sizeof(dst),
	    dstport, sizeof(dstport), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
		dst[0] = dstport[0] = '\0';

	if (!ipv6) {
		struct sockaddr_in *sin = (struct sockaddr_in *)rsa;
		mc = IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rsa;
		mc = IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
	}

	printf("\tvni %d", vni);
	printf(" AWS-ENI-ID %lx", aws_eni_id);
	if (ether) {
		printf(" ether");
	}
	printf(" local %s%s%s:%s", ipv6 ? "[" : "", src, ipv6 ? "]" : "",
	    srcport);
	printf(" %s %s%s%s:%s", mc ? "group" : "remote", ipv6 ? "[" : "",
	    dst, ipv6 ? "]" : "", dstport);

	if (verbose) {
		printf("\n\t\tconfig: ");
		printf("%slearning portrange %d-%d ttl %d",
		    cfg.gnvc_learn ? "" : "no", cfg.gnvc_port_min,
		    cfg.gnvc_port_max, cfg.gnvc_ttl);
		printf("\n\t\tftable: ");
		printf("cnt %d max %d timeout %d",
		    cfg.gnvc_ftable_cnt, cfg.gnvc_ftable_max,
		    cfg.gnvc_ftable_timeout);
	}

	putchar('\n');
}

#define _LOCAL_ADDR46 \
    (GENEVE_PARAM_WITH_LOCAL_ADDR4 | GENEVE_PARAM_WITH_LOCAL_ADDR6)
#define _REMOTE_ADDR46 \
    (GENEVE_PARAM_WITH_REMOTE_ADDR4 | GENEVE_PARAM_WITH_REMOTE_ADDR6)

static void
geneve_check_params(void)
{

	if ((params.gnvp_with & _LOCAL_ADDR46) == _LOCAL_ADDR46)
		errx(1, "cannot specify both local IPv4 and IPv6 addresses");
	if ((params.gnvp_with & _REMOTE_ADDR46) == _REMOTE_ADDR46)
		errx(1, "cannot specify both remote IPv4 and IPv6 addresses");
	if ((params.gnvp_with & GENEVE_PARAM_WITH_LOCAL_ADDR4 &&
	     params.gnvp_with & GENEVE_PARAM_WITH_REMOTE_ADDR6) ||
	    (params.gnvp_with & GENEVE_PARAM_WITH_LOCAL_ADDR6 &&
	     params.gnvp_with & GENEVE_PARAM_WITH_REMOTE_ADDR4))
		errx(1, "cannot mix IPv4 and IPv6 addresses");
}

#undef _LOCAL_ADDR46
#undef _REMOTE_ADDR46

static void
geneve_cb(int s, void *arg)
{

}

static void
geneve_create(int s, struct ifreq *ifr)
{

	geneve_check_params();

	ifr->ifr_data = (caddr_t) &params;
	ioctl_ifcreate(s, ifr);
}

static
DECL_CMD_FUNC(setgeneve_vni, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= GENEVE_VNI_MAX)
		errx(1, "invalid network identifier: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_VNI;
		params.gnvp_vni = val;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_vni = val;

	if (do_cmd(s, GENEVE_CMD_SET_VNI, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_VNI");
}

static
DECL_CMD_FUNC(setgeneve_aws_eni_id, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0)
		errx(1, "invalid AWS ENI ID: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_AWS_ENI_ID;
		params.gnvp_aws_eni_id = val;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_aws_eni_id = val;

	if (do_cmd(s, GENEVE_CMD_SET_AWS_ENI_ID, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_AWS_ENI_ID");
}

static
DECL_CMD_FUNC(setgeneve_local, addr, d)
{
	struct ifgenevecmd cmd;
	struct addrinfo *ai;
	struct sockaddr *sa;
	int error;

	bzero(&cmd, sizeof(cmd));

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing local address string: %s",
		    gai_strerror(error));

	sa = ai->ai_addr;

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "local address cannot be multicast");

		cmd.gnvcmd_sa.in4 = *sin;
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "local address cannot be multicast");

		cmd.gnvcmd_sa.in6 = *sin6;
		break;
	}
#endif
	default:
		errx(1, "local address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (!geneve_exists(s)) {
		if (cmd.gnvcmd_sa.sa.sa_family == AF_INET) {
			params.gnvp_with |= GENEVE_PARAM_WITH_LOCAL_ADDR4;
			params.gnvp_local_sa.in4 = cmd.gnvcmd_sa.in4;
		} else {
			params.gnvp_with |= GENEVE_PARAM_WITH_LOCAL_ADDR6;
			params.gnvp_local_sa.in6 = cmd.gnvcmd_sa.in6;
		}
		return;
	}

	if (do_cmd(s, GENEVE_CMD_SET_LOCAL_ADDR, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_LOCAL_ADDR");
}

static
DECL_CMD_FUNC(setgeneve_remote, addr, d)
{
	struct ifgenevecmd cmd;
	struct addrinfo *ai;
	struct sockaddr *sa;
	int error;

	bzero(&cmd, sizeof(cmd));

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing remote address string: %s",
		    gai_strerror(error));

	sa = ai->ai_addr;

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "remote address cannot be multicast");

		cmd.gnvcmd_sa.in4 = *sin;
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "remote address cannot be multicast");

		cmd.gnvcmd_sa.in6 = *sin6;
		break;
	}
#endif
	default:
		errx(1, "remote address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (!geneve_exists(s)) {
		if (cmd.gnvcmd_sa.sa.sa_family == AF_INET) {
			params.gnvp_with |= GENEVE_PARAM_WITH_REMOTE_ADDR4;
			params.gnvp_remote_sa.in4 = cmd.gnvcmd_sa.in4;
		} else {
			params.gnvp_with |= GENEVE_PARAM_WITH_REMOTE_ADDR6;
			params.gnvp_remote_sa.in6 = cmd.gnvcmd_sa.in6;
		}
		return;
	}

	if (do_cmd(s, GENEVE_CMD_SET_REMOTE_ADDR, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_REMOTE_ADDR");
}

static
DECL_CMD_FUNC(setgeneve_group, addr, d)
{
	struct ifgenevecmd cmd;
	struct addrinfo *ai;
	struct sockaddr *sa;
	int error;

	bzero(&cmd, sizeof(cmd));

	if ((error = getaddrinfo(addr, NULL, NULL, &ai)) != 0)
		errx(1, "error in parsing group address string: %s",
		    gai_strerror(error));

	sa = ai->ai_addr;

	switch (ai->ai_family) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		if (!IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			errx(1, "group address must be multicast");

		cmd.gnvcmd_sa.in4 = *sin;
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		if (!IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			errx(1, "group address must be multicast");

		cmd.gnvcmd_sa.in6 = *sin6;
		break;
	}
#endif
	default:
		errx(1, "group address %s not supported", addr);
	}

	freeaddrinfo(ai);

	if (!geneve_exists(s)) {
		if (cmd.gnvcmd_sa.sa.sa_family == AF_INET) {
			params.gnvp_with |= GENEVE_PARAM_WITH_REMOTE_ADDR4;
			params.gnvp_remote_sa.in4 = cmd.gnvcmd_sa.in4;
		} else {
			params.gnvp_with |= GENEVE_PARAM_WITH_REMOTE_ADDR6;
			params.gnvp_remote_sa.in6 = cmd.gnvcmd_sa.in6;
		}
		return;
	}

	if (do_cmd(s, GENEVE_CMD_SET_REMOTE_ADDR, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_REMOTE_ADDR");
}

static
DECL_CMD_FUNC(setgeneve_local_port, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid local port: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_LOCAL_PORT;
		params.gnvp_local_port = val;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_port = val;

	if (do_cmd(s, GENEVE_CMD_SET_LOCAL_PORT, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_LOCAL_PORT");
}

static
DECL_CMD_FUNC(setgeneve_remote_port, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || val >= UINT16_MAX)
		errx(1, "invalid remote port: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_REMOTE_PORT;
		params.gnvp_remote_port = val;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_port = val;

	if (do_cmd(s, GENEVE_CMD_SET_REMOTE_PORT, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_REMOTE_PORT");
}

static
DECL_CMD_FUNC2(setgeneve_port_range, arg1, arg2)
{
	struct ifgenevecmd cmd;
	u_long min, max;

	if (get_val(arg1, &min) < 0 || min >= UINT16_MAX)
		errx(1, "invalid port range minimum: %s", arg1);
	if (get_val(arg2, &max) < 0 || max >= UINT16_MAX)
		errx(1, "invalid port range maximum: %s", arg2);
	if (max < min)
		errx(1, "invalid port range");

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_PORT_RANGE;
		params.gnvp_min_port = min;
		params.gnvp_max_port = max;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_port_min = min;
	cmd.gnvcmd_port_max = max;

	if (do_cmd(s, GENEVE_CMD_SET_PORT_RANGE, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_PORT_RANGE");
}

static
DECL_CMD_FUNC(setgeneve_timeout, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid timeout value: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_FTABLE_TIMEOUT;
		params.gnvp_ftable_timeout = val & 0xFFFFFFFF;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_ftable_timeout = val & 0xFFFFFFFF;

	if (do_cmd(s, GENEVE_CMD_SET_FTABLE_TIMEOUT, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_FTABLE_TIMEOUT");
}

static
DECL_CMD_FUNC(setgeneve_maxaddr, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xFFFFFFFF) != 0)
		errx(1, "invalid maxaddr value: %s",  arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_FTABLE_MAX;
		params.gnvp_ftable_max = val & 0xFFFFFFFF;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_ftable_max = val & 0xFFFFFFFF;

	if (do_cmd(s, GENEVE_CMD_SET_FTABLE_MAX, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_FTABLE_MAX");
}

static
DECL_CMD_FUNC(setgeneve_dev, arg, d)
{
	struct ifgenevecmd cmd;

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_MULTICAST_IF;
		strlcpy(params.gnvp_mc_ifname, arg,
		    sizeof(params.gnvp_mc_ifname));
		return;
	}

	bzero(&cmd, sizeof(cmd));
	strlcpy(cmd.gnvcmd_ifname, arg, sizeof(cmd.gnvcmd_ifname));

	if (do_cmd(s, GENEVE_CMD_SET_MULTICAST_IF, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_MULTICAST_IF");
}

static
DECL_CMD_FUNC(setgeneve_ttl, arg, d)
{
	struct ifgenevecmd cmd;
	u_long val;

	if (get_val(arg, &val) < 0 || val > 256)
		errx(1, "invalid TTL value: %s", arg);

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_TTL;
		params.gnvp_ttl = val;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	cmd.gnvcmd_ttl = val;

	if (do_cmd(s, GENEVE_CMD_SET_TTL, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_TTL");
}

static
DECL_CMD_FUNC(setgeneve_learn, arg, d)
{
	struct ifgenevecmd cmd;

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_LEARN;
		params.gnvp_learn = d;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	if (d != 0)
		cmd.gnvcmd_flags |= GENEVE_CMD_FLAG_LEARN;

	if (do_cmd(s, GENEVE_CMD_SET_LEARN, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_LEARN");
}

static
DECL_CMD_FUNC(setgeneve_ether, arg, d)
{
	struct ifgenevecmd cmd;

	if (!geneve_exists(s)) {
		params.gnvp_with |= GENEVE_PARAM_WITH_ETHER;
		params.gnvp_ether = d;
		return;
	}

	bzero(&cmd, sizeof(cmd));
	if (d != 0)
		cmd.gnvcmd_flags |= GENEVE_CMD_FLAG_ETHER;

	if (do_cmd(s, GENEVE_CMD_SET_ETHER, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_SET_ETHER");
}

static void
setgeneve_flush(const char *val, int d, int s, const struct afswtch *afp)
{
	struct ifgenevecmd cmd;

	bzero(&cmd, sizeof(cmd));
	if (d != 0)
		cmd.gnvcmd_flags |= GENEVE_CMD_FLAG_FLUSH_ALL;

	if (do_cmd(s, GENEVE_CMD_FLUSH, &cmd, sizeof(cmd), 1) < 0)
		err(1, "GENEVE_CMD_FLUSH");
}

static struct cmd geneve_cmds[] = {

	DEF_CLONE_CMD_ARG("vni",                setgeneve_vni),
	DEF_CLONE_CMD_ARG("geneveid",		setgeneve_vni),
	DEF_CLONE_CMD_ARG("geneveawseniid",	setgeneve_aws_eni_id),
	DEF_CLONE_CMD_ARG("genevelocal",	setgeneve_local),
	DEF_CLONE_CMD_ARG("geneveremote",	setgeneve_remote),
	DEF_CLONE_CMD_ARG("genevegroup",	setgeneve_group),
	DEF_CLONE_CMD_ARG("genevelocalport",	setgeneve_local_port),
	DEF_CLONE_CMD_ARG("geneveremoteport",	setgeneve_remote_port),
	DEF_CLONE_CMD_ARG2("geneveportrange",	setgeneve_port_range),
	DEF_CLONE_CMD_ARG("genevetimeout",	setgeneve_timeout),
	DEF_CLONE_CMD_ARG("genevemaxaddr",	setgeneve_maxaddr),
	DEF_CLONE_CMD_ARG("genevedev",		setgeneve_dev),
	DEF_CLONE_CMD_ARG("genevettl",		setgeneve_ttl),
	DEF_CLONE_CMD("genevelearn", 1,		setgeneve_learn),
	DEF_CLONE_CMD("-genevelearn", 0,	setgeneve_learn),
	DEF_CLONE_CMD("geneveether", 1,		setgeneve_ether),
	DEF_CLONE_CMD("-geneveether", 0,	setgeneve_ether),

	DEF_CMD_ARG("vni",			setgeneve_vni),
	DEF_CMD_ARG("geneveid",			setgeneve_vni),
	DEF_CMD_ARG("geneveawseniid",			setgeneve_aws_eni_id),
	DEF_CMD_ARG("genevelocal",		setgeneve_local),
	DEF_CMD_ARG("geneveremote",		setgeneve_remote),
	DEF_CMD_ARG("genevegroup",		setgeneve_group),
	DEF_CMD_ARG("genevelocalport",		setgeneve_local_port),
	DEF_CMD_ARG("geneveremoteport",		setgeneve_remote_port),
	DEF_CMD_ARG2("geneveportrange",		setgeneve_port_range),
	DEF_CMD_ARG("genevetimeout",		setgeneve_timeout),
	DEF_CMD_ARG("genevemaxaddr",		setgeneve_maxaddr),
	DEF_CMD_ARG("genevedev",			setgeneve_dev),
	DEF_CMD_ARG("genevettl",			setgeneve_ttl),
	DEF_CMD("genevelearn", 1,		setgeneve_learn),
	DEF_CMD("-genevelearn", 0,		setgeneve_learn),
	DEF_CMD("geneveether", 1,		setgeneve_ether),
	DEF_CMD("-geneveether", 0,		setgeneve_ether),

	DEF_CMD("geneveflush", 0,		setgeneve_flush),
	DEF_CMD("geneveflushall", 1,		setgeneve_flush),

	DEF_CMD("genevehwcsum",	IFCAP_GENEVE_HWCSUM,	setifcap),
	DEF_CMD("-genevehwcsum",	-IFCAP_GENEVE_HWCSUM,	setifcap),
	DEF_CMD("genevehwtso",	IFCAP_GENEVE_HWTSO,	setifcap),
	DEF_CMD("-genevehwtso",	-IFCAP_GENEVE_HWTSO,	setifcap),
};

static struct afswtch af_geneve = {
	.af_name		= "af_geneve",
	.af_af			= AF_UNSPEC,
	.af_other_status	= geneve_status,
};

static __constructor void
geneve_ctor(void)
{
	size_t i;

	for (i = 0; i < nitems(geneve_cmds); i++)
		cmd_register(&geneve_cmds[i]);
	af_register(&af_geneve);
	callback_register(geneve_cb, NULL);
	clone_setdefcallback_prefix("geneve", geneve_create);
}
