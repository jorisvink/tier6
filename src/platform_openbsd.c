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
#include <sys/event.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tier6.h"

#define EVENTS_MAX	256

static int	kfd = -1;

void
tier6_platform_init(void)
{
	PRECOND(kfd == -1);

	if ((kfd = kqueue()) == -1)
		fatal("kqueue: %s", errno_s);
}

void
tier6_platform_io_wait(void)
{
	struct tier6_io		*io;
	struct timespec		timeo;
	int			i, nfd;
	struct kevent		events[EVENTS_MAX];

	PRECOND(kfd != -1);

	timeo.tv_sec = 1;
	timeo.tv_nsec = 0;

	if ((nfd = kevent(kfd, NULL, 0, events, EVENTS_MAX, &timeo)) == -1) {
		if (errno == EINTR)
			return;
		fatal("kevent: %s", errno_s);
	}

	if (nfd == 0)
		return;

	for (i = 0; i < nfd; i++) {
		if (events[i].udata == NULL)
			fatal("kqueue event has no udata");

		io = events[i].udata;

		if (events[i].filter == EVFILT_READ)
			io->flags |= TIER6_IO_READABLE;

		io->handle(events[i].udata);
	}
}

void
tier6_platform_io_schedule(int fd, void *udata)
{
	struct kevent	event[1];

	PRECOND(fd >= 0);
	PRECOND(udata != NULL);

	EV_SET(&event[0], fd, EVFILT_READ, EV_ADD, 0, 0, udata);

	if (kevent(kfd, event, 1, NULL, 0, NULL) == -1 && errno != ENOENT)
		fatal("kevent: %s", errno_s);
}

int
tier6_platform_tap_init(const char *name)
{
	char		path[128];
	int		fd, idx, len, flags;

	PRECOND(name != NULL);

	for (idx = 0; idx < 256; idx++) {
		len = snprintf(path, sizeof(path), "/dev/tap%d", idx);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("/dev/tap%d too long", idx);

		if ((fd = open(path, O_RDWR)) != -1)
			break;
	}

	if (idx == 256)
		fatal("unable to find free tap device");

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}

ssize_t
tier6_platform_tap_read(int fd, void *data, size_t len)
{
	PRECOND(fd >= 0);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (read(fd, data, len));
}

ssize_t
tier6_platform_tap_write(int fd, const void *data, size_t len)
{
	PRECOND(fd >= 0);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (write(fd, data, len));
}
