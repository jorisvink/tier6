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
#include <time.h>
#include <unistd.h>

#include "tier6.h"

struct tier6	*t6;

int
main(int argc, char **argv)
{
	struct timespec		ts;

	if (argc != 2)
		fatal("tier6 [config]");

	if ((t6 = calloc(1, sizeof(*t6))) == NULL)
		fatal("failed to allocate t6 context");

	tier6_config(argv[1]);
	tier6_platform_init();

	tier6_tap_init();
	tier6_peer_init();
	tier6_discovery_init();

	for (;;) {
		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		t6->now = ts.tv_sec;

		tier6_platform_io_wait();
		tier6_peer_update();
		tier6_discovery_update();
	}

	return (0);
}

void
tier6_socket_nonblock(int fd)
{
	int		flags;

	PRECOND(fd >= 0);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fnctl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fnctl: %s", errno_s);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf("\n");

	exit(1);
}
