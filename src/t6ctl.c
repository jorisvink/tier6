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

/*
 * The type of stats we can dump when received from tier6.
 */
#define T6CTL_STAT_CATHEDRAL		1
#define T6CTL_STAT_PEER			2

/* The path to our client socket. */
#define T6CTL_CLIENT_SOCKET		"/tmp/tier6ctl.client"

static void	usage(void) __attribute__((noreturn));

static void	ctl_info(int);
static void	ctl_status(int);
static void	ctl_show_stats(struct tier6_ctl_stats *, u_int16_t);

static int	ctl_recv(int, void *, size_t);
static void	ctl_send(int, struct tier6_ctl_request *);
static void	ctl_unix_fill(struct sockaddr_un *, const char *);

/* The control socket we are talking too. */
static const char	*ctlpath = NULL;

static void
usage(void)
{
	printf("tier6ctl [-c path] [command]\n");
	printf("flags:\n");
	printf("    -c <path>  - The control path for the tier6 instance\n");
	printf("\n");
	printf("commands:\n");
	printf("    status     - Show current status\n");
	printf("    whoami     - Show local tier6 configuration\n");
	exit(1);
}

/*
 * t6ctl - A tool to display information from the tier6 daemon.
 */
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

	if (unlink(T6CTL_CLIENT_SOCKET) == -1 && errno != ENOENT)
		err(1, "failed to remove stale tier6ctl socket");

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	ctl_unix_fill(&sun, T6CTL_CLIENT_SOCKET);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "bind");

	if (!strcmp(argv[0], "status")) {
		ctl_status(fd);
	} else if (!strcmp(argv[0], "whoami")) {
		ctl_info(fd);
	} else {
		errx(1, "unknown command '%s'", argv[0]);
	}

	close(fd);

	return (0);
}

/*
 * Fill in a sockaddr_un with the given path.
 */
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

/*
 * Send a request to our tier6 daemon.
 */
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

/*
 * Receive a given amount of bytes from our tier6 daemon. If not
 * all bytes are received we fatal, returns -1 on EOF.
 */
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

/*
 * The "status" command. Display all peer information regarding discovery
 * and for each tunnel that is running.
 */
static void
ctl_status(int fd)
{
	struct tier6_ctl_request	req;
	struct tier6_ctl_peer		peer;
	union tier6_ctl_response	resp;

	memset(&req, 0, sizeof(req));
	req.type = TIER6_CTL_REQUEST_INFO;
	ctl_send(fd, &req);

	if (ctl_recv(fd, &resp, sizeof(resp)) == -1)
		errx(1, "unexpected result from tier6 daemon");

	printf("device\n");
	printf("  kek-id\t\t%02x\n", resp.info.kek_id);
	printf("  cathedral-id\t\t%08x\n", resp.info.cs_id);
	printf("\n");

	printf("discovery\n");
	ctl_show_stats(&resp.info.cathedral, T6CTL_STAT_CATHEDRAL);

	memset(&req, 0, sizeof(req));
	req.type = TIER6_CTL_REQUEST_PEERS;
	ctl_send(fd, &req);

	for (;;) {
		if (ctl_recv(fd, &peer, sizeof(peer)) == -1)
			errx(1, "unexpected result from tier6 daemon");

		if (peer.state == 0)
			break;

		printf("\ntunnel %02x <-> %02x\n",
		    resp.info.kek_id, peer.peer.id);
		ctl_show_stats(&peer.peer, T6CTL_STAT_PEER);
		printf("\n");
		ctl_show_stats(&peer.cathedral, T6CTL_STAT_CATHEDRAL);
	}
}

/*
 * Show stat information for a tier6_ctl_stats. This can be either
 * a cathedral or a peer, and depending on what it is we show different
 * type of information.
 */
static void
ctl_show_stats(struct tier6_ctl_stats *stat, u_int16_t which)
{
	struct in_addr		in;
	struct timespec		ts;
	time_t			now;
	const char		*prefix;
	float			rx, tx, last;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);

	if (stat->last > 0)
		last = (now - stat->last) / 1000.0f;
	else
		last = 0;

	in.s_addr = stat->ip;
	rx = stat->rx_bytes / 1024.0f / 1024.0f;
	tx = stat->tx_bytes / 1024.0f / 1024.0f;

	switch (which) {
	case T6CTL_STAT_CATHEDRAL:
		prefix = "using cathedral";
		break;
	case T6CTL_STAT_PEER:
		prefix = "peer";
		break;
	default:
		errx(1, "unknown peer type %d", which);
	}

	printf("  %s\n", prefix);
	printf("      ipv4\t\t%s:%u\n", inet_ntoa(in), ntohs(stat->port));

	if (which == T6CTL_STAT_PEER)
		printf("      rx/tx\t\t%.2f / %.2f MiB\n", rx, tx);

	printf("      last packet\t%.2f seconds ago\n", last);
}

/*
 * The "whoami" command, shows basic configuration information.
 */
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
