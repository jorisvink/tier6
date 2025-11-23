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
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tier6.h"

/* Maximum number of events in one single epoll_wait() call. */
#define EVENTS_MAX	256

/* The epoll fd use. */
static int	efd = -1;

/*
 * Initialise the Linux platform.
 */
void
tier6_platform_init(void)
{
	PRECOND(efd == -1);

	if ((efd = epoll_create(1)) == -1)
		fatal("epoll_create: %s", errno_s);
}

/*
 * Apply sandboxing to our process.
 */
void
tier6_platform_sandbox(void)
{
	tier6_drop_user();
}

/*
 * Wait for any i/o to occur on previously registered sockets.
 * The maximum wait time is 1 second.
 */
void
tier6_platform_io_wait(void)
{
	struct tier6_io		*io;
	int			i, nfd;
	struct epoll_event	events[EVENTS_MAX];

	PRECOND(efd != -1);

	if ((nfd = epoll_wait(efd, events, EVENTS_MAX, 1000)) == -1) {
		if (errno == EINTR)
			return;
		fatal("epoll_wait: %s", errno_s);
	}

	if (nfd == 0)
		return;

	for (i = 0; i < nfd; i++) {
		if (events[i].data.ptr == NULL)
			fatal("epoll event has no data.ptr");

		io = events[i].data.ptr;

		if (events[i].events & EPOLLIN)
			io->flags |= TIER6_IO_READABLE;

		io->handle(events[i].data.ptr);
	}
}

/*
 * Schedule the given fd into our event loop, and tie it together
 * with the user data pointer.
 */
void
tier6_platform_io_schedule(int fd, void *udata)
{
	struct epoll_event	evt;

	PRECOND(fd >= 0);
	PRECOND(udata != NULL);

	evt.data.ptr = udata;
	evt.events = EPOLLIN | EPOLLET;

	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl(), modication: %s", errno_s);
		}
		fatal("epoll_ctl(), addition: %s", errno_s);
	}
}

/*
 * Create our named tap device.
 */
int
tier6_platform_tap_init(const char *tap)
{
	struct ifreq		ifr;
	int			len, fd;

	PRECOND(tap != NULL);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
		fatal("failed to open /dev/net/tun: %s", errno_s);

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", tap);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("tap interface name '%s' too large", tap);

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
		fatal("failed to create tap device %s: %s", tap, errno_s);

	tier6_log(LOG_INFO, "interface '%s' created", tap);

	return (fd);
}

/*
 * Read a frame from our tap device.
 */
ssize_t
tier6_platform_tap_read(int fd, void *data, size_t len)
{
	PRECOND(fd >= 0);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (read(fd, data, len));
}

/*
 * Write a frame from our tap device.
 */
ssize_t
tier6_platform_tap_write(int fd, const void *data, size_t len)
{
	PRECOND(fd >= 0);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (write(fd, data, len));
}
