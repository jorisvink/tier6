/*
 * Copyright (c) 2025-2026 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __H_TIER6_H
#define __H_TIER6_H

#if defined(__APPLE__)
#define daemon portability_is_king
#endif

#include <sys/queue.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <libkyrka/libkyrka.h>

#include "tier6_ctl.h"

/* Portability for macos. */
#if defined(__APPLE__)
#undef daemon
extern int daemon(int, int);

#include <libkern/OSByteOrder.h>
#define htobe16(x)		OSSwapHostToBigInt16(x)
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#define be16toh(x)		OSSwapBigToHostInt16(x)
#define be32toh(x)		OSSwapBigToHostInt32(x)
#define be64toh(x)		OSSwapBigToHostInt64(x)
#endif

/* A few handy macros. */
#define errno_s		strerror(errno)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			fatal("verification failed in %s:%s:%d",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* Length of an ethernet MAC address. */
#define TIER6_ETHERNET_MAC_LEN		6

/* The ethernet protocols we will allow. */
#define TIER6_ETHER_TYPE_VLAN		0x8100
#define TIER6_ETHER_TYPE_ARP		0x0806
#define TIER6_ETHER_TYPE_IPV4		0x0800
#define TIER6_ETHER_TYPE_IPV6		0x86dd

/* Special ethernet type for heartbeats. */
#define TIER6_ETHER_TYPE_HEARTBEAT	0xdead

/* Special ethernet type for discovery probe. */
#define TIER6_ETHER_TYPE_DISC_PROBE	0xdeae

/* Special ethernet type for discovery ack. */
#define TIER6_ETHER_TYPE_DISC_ACK	0xdeaf

/*
 * An ethernet frame header.
 */
struct tier6_ether {
	u_int8_t	dst[TIER6_ETHERNET_MAC_LEN];
	u_int8_t	src[TIER6_ETHERNET_MAC_LEN];
	u_int16_t	proto;
} __attribute__((packed));

/* Maximum number of IPv4 addresses we send to our peer in a heartbeat. */
#define TIER6_HB_IPV4_MAX	32

/*
 * A heartbeat packet.
 */
struct tier6_hb {
	struct tier6_ether	eth;
	u_int16_t		port;
	u_int32_t		ips[TIER6_HB_IPV4_MAX];
	u_int32_t		masks[TIER6_HB_IPV4_MAX];
} __attribute__((packed));

/*
 * A discovery probe/ack.
 */
struct tier6_discovery {
	struct tier6_ether	eth;
} __attribute__((packed));

/*
 * An i/o event callback with user data.
 */
#define TIER6_IO_READABLE		(1 << 0)

struct tier6_io {
	u_int32_t	flags;
	void		(*handle)(void *);
};

/*
 * A mac address we discovered on a peer.
 *
 * Right now this is a simple linked-list on which we perform an
 * exhaustive search to see if a frame destination mac matches
 * a mac on this list.
 *
 * While this isn't ideal unless it becomes a measurable bottleneck
 * this keeps the code nice and tidy.
 */
struct tier6_mac {
	time_t				age;
	int				fixed;
	u_int8_t			addr[TIER6_ETHERNET_MAC_LEN];

	LIST_ENTRY(tier6_mac)		list;
};

/*
 * The seconds before we consider a cathedral timed out if we've
 * not heard from it yet.
 */
#define TIER6_CATHEDRAL_TIMEOUT_INIT	(10 * 1000)

/*
 * The seconds before we consider a cathedral timed out if we've
 * managed to talk to it before.
 */
#define TIER6_CATHEDRAL_TIMEOUT		(45 * 1000)

/*
 * A cathedral we are talking to and the last time we heard from it.
 */
struct tier6_cathedral {
	time_t				last;
	u_int32_t			timeout;
	struct sockaddr_in		addr;
};

/*
 * A tier6 peer we are talking to.
 */
struct tier6_peer {
	struct tier6_io			io;

	int				fd;
	u_int8_t			id;
	u_int16_t			port;
	int				local_discovery;

	struct sockaddr_in		addr;
	struct tier6_cathedral		cathedral;

	u_int64_t			rx_bytes;
	u_int64_t			tx_bytes;

	time_t				alive;
	time_t				hb_next;
	u_int32_t			hb_ticks;
	u_int32_t			hb_frequency;

	KYRKA				*ctx;

	LIST_HEAD(, tier6_mac)		macs;
	LIST_ENTRY(tier6_peer)		list;
};

#define TIER6_FLAG_SHROUD		(1 << 0)

/*
 * Global tier6 data structure holding configuration etc.
 */
struct tier6 {
	u_int32_t		flags;
	u_int64_t		flock;
	u_int32_t		cs_id;
	u_int8_t		kek_id;
	u_int16_t		mtu;

	char			*runas;
	char			*bridge;
	char			*tapname;
	char			*control;
	char			*remembrance;

	char			*cs_path;
	char			*kek_path;
	char			*cosk_path;

	time_t			now;

	struct tier6_cathedral	cathedral;
};

/* from $(OBJDIR)/version.c */
extern const char	*tier6_build_rev;
extern const char	*tier6_build_date;

/* from src/platform_linux.c */
#if defined(__linux__)
extern int		linux_seccomp_tracing;
#endif

/* src/config.c */
void	tier6_config(const char *);

/* src/control.c */
void	tier6_control_init(void);

/* src/discovery.c */
void	tier6_discovery_init(void);
void	tier6_discovery_update(void);

/* src/peer.c */
void	tier6_peer_init(void);
void	tier6_peer_update(void);
void	tier6_peer_state(u_int8_t, u_int8_t);
void	tier6_peer_output(const void *, size_t);
void	tier6_peer_info(union tier6_ctl_response *);

/* src/remembrance.c */
void	tier6_remembrance_load(void);
int	tier6_remembrance_cathedral(struct tier6_cathedral *);
void	tier6_remembrance_save(struct kyrka_event_remembrance *);

/* src/tier6.c */
void	tier6_drop_user(void);
void	tier6_socket_nonblock(int);
void	tier6_set_encapsulation(KYRKA *);
void	tier6_log(int, const char *, ...)
	    __attribute__((format (printf, 2, 3)));
void	tier6_logv(int, const char *, va_list);
int	tier6_inet_match(struct sockaddr_in *, struct sockaddr_in *);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
	    __attribute__((noreturn));

const char	*tier6_address(struct sockaddr_in *);

extern struct tier6	*t6;

/* platform bits. */
void	tier6_platform_init(void);
void	tier6_platform_sandbox(void);

void	tier6_platform_tap_configure(struct in_addr *);
ssize_t	tier6_platform_tap_write(const void *, size_t);

void	tier6_platform_io_wait(void);
void	tier6_platform_io_schedule(int, void *);

#endif
