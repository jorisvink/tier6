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

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

static void	discovery_io_read(void);
static void	discovery_io_event(void *);

static void	discovery_kyrka_event(KYRKA *, union kyrka_event *, void *);
static void	discovery_kyrka_send(const void *, size_t, u_int64_t, void *);

static struct {
	struct tier6_io		io;
	int			fd;
	time_t			at;
	struct sockaddr_in	addr;
	KYRKA			*ctx;
} discovery;

void
tier6_discovery_init(void)
{
	struct kyrka_cathedral_cfg	cfg;

	memset(&discovery, 0, sizeof(discovery));

	if ((discovery.fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	discovery.io.handle = discovery_io_event;
	memcpy(&discovery.addr, &t6->cathedral, sizeof(t6->cathedral));

	tier6_socket_nonblock(discovery.fd);
	tier6_platform_io_schedule(discovery.fd, &discovery);

	discovery.ctx = kyrka_ctx_alloc(discovery_kyrka_event, NULL);
	if (discovery.ctx == NULL)
		fatal("failed to create discovery context");

	memset(&cfg, 0, sizeof(cfg));

	cfg.group = 0x0001;
	cfg.tunnel = t6->kek_id;
	cfg.identity = t6->cs_id;
	cfg.flock_src = t6->flock;
	cfg.flock_dst = t6->flock;

	cfg.cosk = t6->cosk_path;
	cfg.secret = t6->cs_path;
	cfg.send = discovery_kyrka_send;

	if (kyrka_cathedral_config(discovery.ctx, &cfg) == -1) {
		fatal("failed to configure cathedral: %d",
		    kyrka_last_error(discovery.ctx));
	}
}

void
tier6_discovery_update(void)
{
	if (discovery.at > 0 && t6->now < discovery.at)
		return;

	discovery.at = t6->now + 1;

	if (kyrka_cathedral_liturgy(discovery.ctx, NULL, 0) == -1) {
		printf("kyrka_cathedral_notify: %d\n",
		    kyrka_last_error(discovery.ctx));
	}
}

static void
discovery_io_event(void *udata)
{
	PRECOND(udata == &discovery);

	if (discovery.io.flags & TIER6_IO_READABLE)
		discovery_io_read();
}

static void
discovery_io_read(void)
{
	ssize_t		ret;
	u_int8_t	buf[1500];

	for (;;) {
		if ((ret = read(discovery.fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				return;
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				discovery.io.flags &= ~TIER6_IO_READABLE;
				break;
			}
			fatal("read: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if (kyrka_purgatory_input(discovery.ctx, buf, ret) == -1) {
			printf("kyrka_purgatory_input: %d\n",
			    kyrka_last_error(discovery.ctx));
		}
	}
}

static void
discovery_kyrka_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	int		idx;

	PRECOND(ctx == discovery.ctx);
	PRECOND(evt != NULL);
	PRECOND(udata == NULL);

	switch (evt->type) {
	case KYRKA_EVENT_LITURGY_RECEIVED:
		for (idx = 1; idx < KYRKA_PEERS_PER_FLOCK; idx++)
			tier6_peer_state(idx, evt->liturgy.peers[idx]);
		break;
	default:
		printf("%s: %u\n", __func__, evt->type);
		break;
	}
}

static void
discovery_kyrka_send(const void *data, size_t len, u_int64_t magic, void *udata)
{
	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata == NULL);

	if (sendto(discovery.fd, data, len, 0,
	    (const struct sockaddr *)&discovery.addr,
	    sizeof(discovery.addr)) == -1)
		printf("sendto: %s\n", errno_s);
}
