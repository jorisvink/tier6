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

static void		linux_tap_io(void *);
static void		linux_tap_create(void);

/* The epoll fd use. */
static int		efd = -1;

/* The io event interface. */
static struct tier6_io	tap_io;

/* The tap fd. */
static int		tap_fd = -1;

/*
 * Initialise the Linux platform.
 */
void
tier6_platform_init(void)
{
	PRECOND(efd == -1);

	if ((efd = epoll_create(1)) == -1)
		fatal("epoll_create: %s", errno_s);

	linux_tap_create();
	tap_io.handle = linux_tap_io;

	tier6_socket_nonblock(tap_fd);
	tier6_platform_io_schedule(tap_fd, &tap_io);
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
 * Write a frame from our tap device.
 */
ssize_t
tier6_platform_tap_write(const void *data, size_t len)
{
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (write(tap_fd, data, len));
}

/*
 * Create our name tap interface based on the tapname configuration.
 */
static void
linux_tap_create(void)
{
	struct ifreq		ifr;
	int			len, fd;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((tap_fd = open("/dev/net/tun", O_RDWR)) == -1)
		fatal("failed to open /dev/net/tun: %s", errno_s);

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", t6->tapname);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("tap interface name '%s' too large", t6->tapname);

	if (ioctl(tap_fd, TUNSETIFF, &ifr) == -1) {
		fatal("failed to create tap device %s: %s",
		    t6->tapname, errno_s);
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	ifr.ifr_hwaddr.sa_family = AF_LOCAL;

	ifr.ifr_hwaddr.sa_data[0] = 0x06;
	ifr.ifr_hwaddr.sa_data[1] = t6->kek_id;
	ifr.ifr_hwaddr.sa_data[2] = (t6->cs_id >> 24) & 0xff;
	ifr.ifr_hwaddr.sa_data[3] = (t6->cs_id >> 16) & 0xff;
	ifr.ifr_hwaddr.sa_data[4] = (t6->cs_id >> 8) & 0xff;
	ifr.ifr_hwaddr.sa_data[5] = t6->cs_id & 0xff;;

	if (ioctl(fd, SIOCSIFHWADDR, &ifr) == -1)
		fatal("ioctl(SIOCSIFHWADDR): %s", errno_s);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCGIFFLAGS): %s", errno_s);

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	(void)close(fd);

	tier6_log(LOG_INFO, "interface '%s' created", t6->tapname);
}

/*
 * Read a frame from our tap interface and inject it into peer tunnels.
 */
static void
linux_tap_io(void *udata)
{
	ssize_t		ret;
	u_int8_t	frame[1500];

	PRECOND(udata == &tap_io);

	for (;;) {
		if ((ret = read(tap_fd, frame, sizeof(frame))) == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				tap_io.flags &= ~TIER6_IO_READABLE;
				return;
			}

			fatal("tap read: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if ((size_t)ret <= sizeof(struct tier6_ether))
			continue;

		tier6_peer_output(frame, ret);
	}
}
