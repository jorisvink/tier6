/*
 * Copyright (c) 2026 Joris Vink <joris@sanctorum.se>
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
#include <sys/un.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libkyrka/libkyrka.h>

#include "tier6_ctl.h"

#define TIER6CTL_CLIENT_SOCKET		"/tmp/tier6ctl.client"

static void	usage(void) __attribute__((noreturn));

static void	ctl_info(int);
static void	ctl_list_peers(int);

static int	ctl_recv(int, void *, size_t);
static void	ctl_send(int, struct tier6_ctl_request *);
static void	ctl_unix_fill(struct sockaddr_un *, const char *);

static const char	*ctlpath;

static void
usage(void)
{
	printf("tier6ctl [-c path] [command]\n");
	printf("flags:\n");
	printf("    -c <path>  - The control path for the tier6 instance\n");
	printf("\n");
	printf("commands:\n");
	printf("    peers      - Show info on all connected peers\n");
	printf("    whoami     - Show local tier6 configuration\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un	sun;
	int			ch, fd;

	ctlpath = NULL;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			ctlpath = optarg;
			break;
		default:
			usage();
		}
	}

	if (ctlpath == NULL)
		errx(1, "no control path (-c) was given");

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	if (unlink(TIER6CTL_CLIENT_SOCKET) == -1 && errno != ENOENT)
		err(1, "failed to remove stale tier6ctl socket");

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	ctl_unix_fill(&sun, TIER6CTL_CLIENT_SOCKET);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "bind");

	if (!strcmp(argv[0], "peers")) {
		ctl_list_peers(fd);
	} else if (!strcmp(argv[0], "whoami")) {
		ctl_info(fd);
	} else {
		errx(1, "unknown command '%s'", argv[0]);
	}

	close(fd);

	return (0);
}

static void
ctl_unix_fill(struct sockaddr_un *sun, const char *path)
{
	int		len;

	memset(sun, 0, sizeof(*sun));

	sun->sun_family = AF_UNIX;

	len = snprintf(sun->sun_path, sizeof(sun->sun_path), "%s", path);
	if (len == -1 || (size_t)len >= sizeof(sun->sun_path))
		errx(1, "socket path '%s' too large", path);

}

static void
ctl_send(int fd, struct tier6_ctl_request *req)
{
	ssize_t			ret;
	struct sockaddr_un	sun;

	ctl_unix_fill(&sun, ctlpath);

	for (;;) {
		if ((ret = sendto(fd, req, sizeof(*req), 0,
		    (const struct sockaddr *)&sun, sizeof(sun))) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "send");
		}

		if ((size_t)ret != sizeof(*req))
			errx(1, "partial send %zd/%zu", ret, sizeof(*req));

		break;
	}
}

static int
ctl_recv(int fd, void *data, size_t len)
{
	ssize_t		ret;

	for (;;) {
		if ((ret = recv(fd, data, len, 0)) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "recv");
		}

		if (ret == 0)
			return (-1);

		if ((size_t)ret != len)
			errx(1, "partial recv %zd/%zu", ret, len);

		break;
	}

	return (0);
}

static void
ctl_list_peers(int fd)
{
	struct timespec			ts;
	struct in_addr			in;
	time_t				now;
	struct tier6_ctl_request	req;
	struct tier6_ctl_peer		peer;
	float				rx, tx, last;

	memset(&req, 0, sizeof(req));
	req.type = TIER6_CTL_REQUEST_PEERS;

	ctl_send(fd, &req);

	for (;;) {
		ctl_recv(fd, &peer, sizeof(peer));

		if (peer.state == 0)
			break;

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		now = ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);

		in.s_addr = peer.addr.ip;
		rx = peer.rx_bytes / 1024.0f / 1024.0f;
		tx = peer.tx_bytes / 1024.0f / 1024.0f;

		if (peer.last > 0)
			last = (now - peer.last) / 1000.0f;
		else
			last = 0;

		printf("%02x - %.2f %.2f MiB - %.2f sec - %s:%u\n", peer.id,
		    rx, tx, last, inet_ntoa(in), ntohs(peer.addr.port));
	}
}

static void
ctl_info(int fd)
{
	struct tier6_ctl_request	req;
	union tier6_ctl_response	resp;

	memset(&req, 0, sizeof(req));
	req.type = TIER6_CTL_REQUEST_INFO;

	ctl_send(fd, &req);

	if (ctl_recv(fd, &resp, sizeof(resp)) == -1)
		errx(1, "unexpected result from tier6 daemon");

	printf("%02x - %" PRIx64 " - %08x\n",
	    resp.info.kek_id, resp.info.flock, resp.info.cs_id);
}
