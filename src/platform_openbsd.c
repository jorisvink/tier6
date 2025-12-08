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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/if_ether.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tier6.h"

/* The number of max events we handle in a single kevent() call. */
#define EVENTS_MAX	256

static void		openbsd_tap_io(void *);
static void		openbsd_tap_create(void);

/* The kqueue() fd. */
static int		kfd = -1;

/* The io event interface. */
static struct tier6_io	tap_io;

/* The tap fd. */
static int		tap_fd = -1;

/*
 * Initialise the OpenBSD platform.
 */
void
tier6_platform_init(void)
{
	PRECOND(kfd == -1);
	PRECOND(tap_fd == -1);

	if ((kfd = kqueue()) == -1)
		fatal("kqueue: %s", errno_s);

	openbsd_tap_create();
	tap_io.handle = openbsd_tap_io;

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
 * Schedule the given fd into our event loop, and tie it together
 * with the user data pointer.
 */
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

/*
 * Create our tap device, unlike Linux we cannot name tap devices and
 * thus are left to use the standard names.
 */
static void
openbsd_tap_create(void)
{
	struct ifreq		ifr;
	char			path[128];
	int			fd, idx, len;

	for (idx = 0; idx < 256; idx++) {
		len = snprintf(path, sizeof(path), "/dev/tap%d", idx);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("/dev/tap%d too long", idx);

		if ((tap_fd = open(path, O_RDWR)) != -1)
			break;
	}

	if (idx == 256)
		fatal("unable to find free tap device");

	tier6_log(LOG_INFO, "using tap device '%s'", path);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	if (strlcpy(ifr.ifr_name, &path[5],
	    sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
		fatal("failed to copy interface name");

	ifr.ifr_data = t6->tapname;

	if (ioctl(fd, SIOCSIFDESCR, &ifr) == -1)
		fatal("ioctl(SIOCSIFDESCR): %s", errno_s);

	ifr.ifr_addr.sa_family = AF_LOCAL;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;

	ifr.ifr_addr.sa_data[0] = 0x06;
	ifr.ifr_addr.sa_data[1] = t6->kek_id;
	ifr.ifr_addr.sa_data[2] = (t6->cs_id >> 24) & 0xff;
	ifr.ifr_addr.sa_data[3] = (t6->cs_id >> 16) & 0xff;
	ifr.ifr_addr.sa_data[4] = (t6->cs_id >> 8) & 0xff;
	ifr.ifr_addr.sa_data[5] = t6->cs_id & 0xff;;

	if (ioctl(fd, SIOCSIFLLADDR, &ifr) == -1)
		fatal("ioctl(SIOCSIFLLADDR): %s", errno_s);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCGIFFLAGS): %s", errno_s);

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	(void)close(fd);
}

/*
 * Read a frame from our tap interface and inject it into peer tunnels.
 */
static void
openbsd_tap_io(void *udata)
{
	ssize_t		ret;
	u_int8_t	frame[1500];

	PRECOND(tap_fd >= 0);
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
