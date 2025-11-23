/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
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

#include <sys/queue.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <libkyrka/libkyrka.h>

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

/*
 * An ethernet frame header.
 */
#define TIER6_ETHERNET_MAC_LEN		6

#define TIER6_ETHER_TYPE_VLAN		0x8100
#define TIER6_ETHER_TYPE_ARP		0x0806
#define TIER6_ETHER_TYPE_IPV4		0x0800
#define TIER6_ETHER_TYPE_IPV6		0x86dd

struct tier6_ether {
	u_int8_t	dst[TIER6_ETHERNET_MAC_LEN];
	u_int8_t	src[TIER6_ETHERNET_MAC_LEN];
	u_int16_t	proto;
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
 */
struct tier6_mac {
	time_t				age;
	int				fixed;
	u_int8_t			addr[TIER6_ETHERNET_MAC_LEN];

	LIST_ENTRY(tier6_mac)		list;
};

/*
 * A tier6 peer we are talking to.
 */
struct tier6_peer {
	struct tier6_io			io;

	int				fd;
	u_int8_t			id;

	struct sockaddr_in		addr;
	struct sockaddr_in		cathedral;

	KYRKA				*ctx;

	LIST_HEAD(, tier6_mac)		macs;
	LIST_ENTRY(tier6_peer)		list;
};

/*
 * Global tier6 data structure holding configuration etc.
 */
struct tier6 {
	u_int64_t		flock;
	u_int32_t		cs_id;
	u_int8_t		kek_id;

	char			*runas;
	char			*tapname;

	char			*cs_path;
	char			*kek_path;
	char			*cosk_path;

	time_t			now;

	struct sockaddr_in	cathedral;
};

/* from $(OBJDIR)/version.c */
extern const char	*tier6_build_rev;
extern const char	*tier6_build_date;

/* src/config.c */
void	tier6_config(const char *);

/* src/discovery.c */
void	tier6_discovery_init(void);
void	tier6_discovery_update(void);

/* src/peer.c */
void	tier6_peer_init(void);
void	tier6_peer_update(void);
void	tier6_peer_state(u_int8_t, u_int8_t);
void	tier6_peer_output(const void *, size_t);

/* src/tap.c */
void	tier6_tap_init(void);
void	tier6_tap_output(const void *, size_t);

/* src/tier6.c */
void	tier6_drop_user(void);
void	tier6_socket_nonblock(int);
void	tier6_log(int, const char *, ...)
	    __attribute__((format (printf, 2, 3)));
void	tier6_logv(int, const char *, va_list);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
	    __attribute__((noreturn));

extern struct tier6	*t6;

/* platform bits. */
void	tier6_platform_init(void);
void	tier6_platform_sandbox(void);

int	tier6_platform_tap_init(const char *);
ssize_t	tier6_platform_tap_read(int, void *, size_t);
ssize_t	tier6_platform_tap_write(int, const void *, size_t);

void	tier6_platform_io_wait(void);
void	tier6_platform_io_schedule(int, void *);

#endif
