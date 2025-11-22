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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "tier6.h"

static void	tap_io_event(void *);

static struct {
	struct tier6_io		io;
	int			fd;
} tap;

void
tier6_tap_init(void)
{
	int		flags;

	tap.io.handle = tap_io_event;
	tap.fd = tier6_platform_tap_init(t6->tapname);

	if ((flags = fcntl(tap.fd, F_GETFL, 0)) == -1)
		fatal("fnctl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(tap.fd, F_SETFL, flags) == -1)
		fatal("fnctl: %s", errno_s);

	tier6_platform_io_schedule(tap.fd, &tap);
}

void
tier6_tap_output(const void *data, size_t len)
{
	PRECOND(data != NULL);
	PRECOND(len > 0);

	if (tier6_platform_tap_write(tap.fd, data, len) == -1)
		printf("failed to write to tap: %s\n", errno_s);
}

static void
tap_io_event(void *udata)
{
	ssize_t		ret;
	u_int8_t	pkt[1500];

	PRECOND(udata == &tap);

	for (;;) {
		ret = tier6_platform_tap_read(tap.fd, pkt, sizeof(pkt));
		if (ret == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				tap.io.flags &= ~TIER6_IO_READABLE;
				return;
			}

			fatal("read from tap: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if ((size_t)ret <= sizeof(struct tier6_ether))
			continue;

		tier6_peer_output(pkt, ret);
	}
}
