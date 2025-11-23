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

/*
 * The autodiscovery of peers uses the sanctum liturgy functionaly
 * to receive updates from a cathedral about what peers have come
 * online and want tunnels.
 */

static void	discovery_io_read(void);
static void	discovery_io_event(void *);

static void	discovery_kyrka_event(KYRKA *, union kyrka_event *, void *);
static void	discovery_kyrka_send(const void *, size_t, u_int64_t, void *);

/* The local i/o event schedule for use in our event loop. */
static struct tier6_io		io;

/* The UDP socket on which we send and receive cathedral data. */
static int			fd;

/* The current configured cathedral address. */
static struct sockaddr_in	addr;

/* Our libkyrka context. */
static KYRKA			*liturgy;

/* The next time we should notify our cathedrals. */
static time_t			next_notify;

/*
 * Initialise our autodiscovery by creating a socket, setting up
 * the libkyrka context and getting the socket setup in our event loop.
 */
void
tier6_discovery_init(void)
{
	struct kyrka_cathedral_cfg	cfg;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	io.handle = discovery_io_event;
	memcpy(&addr, &t6->cathedral, sizeof(t6->cathedral));

	tier6_socket_nonblock(fd);
	tier6_platform_io_schedule(fd, &io);

	if ((liturgy = kyrka_ctx_alloc(discovery_kyrka_event, NULL)) == NULL)
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

	if (kyrka_cathedral_config(liturgy, &cfg) == -1) {
		fatal("failed to configure cathedral: %d",
		    kyrka_last_error(liturgy));
	}
}

/*
 * We update our cathedrals once every second about our presence.
 */
void
tier6_discovery_update(void)
{
	if (next_notify > 0 && t6->now < next_notify)
		return;

	next_notify = t6->now + 1;

	if (kyrka_cathedral_liturgy(liturgy, NULL, 0) == -1) {
		tier6_log(LOG_NOTICE, "discovery kyrka_cathedral_notify: %d",
		    kyrka_last_error(liturgy));
	}
}

/*
 * Callback for when an event occurred on our liturgy socket.
 */
static void
discovery_io_event(void *udata)
{
	PRECOND(udata == &io);

	if (io.flags & TIER6_IO_READABLE)
		discovery_io_read();
}

/*
 * Attempt to read packets from our liturgy socket and push them
 * into the libkyrka context so they get handled.
 */
static void
discovery_io_read(void)
{
	ssize_t		ret;
	u_int8_t	buf[1500];

	for (;;) {
		if ((ret = read(fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				return;
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				io.flags &= ~TIER6_IO_READABLE;
				break;
			}
			fatal("read: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if (kyrka_purgatory_input(liturgy, buf, ret) == -1) {
			tier6_log(LOG_NOTICE,
			    "discovery kyrka_purgatory_input: %d",
			    kyrka_last_error(liturgy));
		}
	}
}

/*
 * Callback from libkyrka when an event occurred on our liturgy context.
 * We only care about the KYRKA_EVENT_LITURGY_RECEIVED event for now.
 */
static void
discovery_kyrka_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	int		idx;

	PRECOND(ctx == liturgy);
	PRECOND(evt != NULL);
	PRECOND(udata == NULL);

	switch (evt->type) {
	case KYRKA_EVENT_LITURGY_RECEIVED:
		for (idx = 1; idx < KYRKA_PEERS_PER_FLOCK; idx++)
			tier6_peer_state(idx, evt->liturgy.peers[idx]);
		break;
	default:
		tier6_log(LOG_NOTICE,
		    "discovery received unexpected event %u", evt->type);
		break;
	}
}

/*
 * Callback from libkyrka when we have data to be sent to the cathedral.
 */
static void
discovery_kyrka_send(const void *data, size_t len, u_int64_t magic, void *udata)
{
	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata == NULL);

	if (sendto(fd, data, len, 0,
	    (const struct sockaddr *)&addr, sizeof(addr)) == -1)
		tier6_log(LOG_NOTICE, "discovery sendto: %s", errno_s);
}
