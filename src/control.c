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
#include <sys/stat.h>
#include <sys/un.h>

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

static void	control_io_event(void *);
static void	control_request_info(struct sockaddr_un *);
static void	control_request_peers(struct sockaddr_un *);

/* The io event interface. */
static struct tier6_io		io;

/* Our local unix socket. */
static int			fd = -1;

/*
 * Initialise our unix control socket on which we can get requests.
 */
void
tier6_control_init(void)
{
	int			len;
	struct sockaddr_un	sun;
	struct passwd		*pw;

	PRECOND(fd == -1);

	if (t6->control == NULL)
		return;

	if ((pw = getpwnam(t6->runas)) == NULL)
		fatal("failed to find runas '%s' (%s)", t6->runas, errno_s);

	if (unlink(t6->control) == -1 && errno != ENOENT)
		fatal("%s: %s", t6->control, errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", t6->control);
	if (len < 0 || (size_t)len >= sizeof(sun.sun_path))
		fatal("control path too large");

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind %s: %s", t6->control, errno_s);

	if (chown(t6->control, pw->pw_uid, pw->pw_gid) == -1)
		fatal("chown %s: %s", t6->control, errno_s);

	if (chmod(t6->control, S_IRWXU) == -1)
		fatal("chmod %s: %s", t6->control, errno_s);

	io.handle = control_io_event;

	tier6_socket_nonblock(fd);
	tier6_platform_io_schedule(fd, &io);
}

/*
 * An event is pending on our control socket, read it and consume it.
 */
static void
control_io_event(void *udata)
{
	ssize_t				ret;
	struct tier6_ctl_request	req;
	struct sockaddr_un		peer;
	socklen_t			peerlen;

	PRECOND(udata == &io);
	PRECOND(fd >= 0);

	for (;;) {
		peerlen = sizeof(peer);
		if ((ret = recvfrom(fd, &req, sizeof(req), 0,
		    (struct sockaddr *)&peer, &peerlen)) == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				io.flags &= ~TIER6_IO_READABLE;
				return;
			}

			fatal("recvfrom: %s", errno_s);
		}

		if ((size_t)ret != sizeof(req))
			continue;

		switch (req.type) {
		case TIER6_CTL_REQUEST_PEERS:
			control_request_peers(&peer);
			break;
		case TIER6_CTL_REQUEST_INFO:
			control_request_info(&peer);
			break;
		default:
			tier6_log(LOG_NOTICE, "unknown ctl request %02x",
			    req.type);
		}
	}
}

/*
 * Handle a TIER6_CTL_REQUEST_PEERS request.
 */
static void
control_request_peers(struct sockaddr_un *peer)
{
	PRECOND(peer != NULL);

	tier6_peer_info(fd, peer);
}

/*
 * Handle a TIER6_CTL_REQUEST_INFO request.
 */
static void
control_request_info(struct sockaddr_un *peer)
{
	union tier6_ctl_response	resp;
	struct tier6_cathedral		cathedral;

	PRECOND(peer != NULL);

	memset(&resp, 0, sizeof(resp));

	resp.info.flock = t6->flock;
	resp.info.cs_id = t6->cs_id;
	resp.info.kek_id = t6->kek_id;

	tier6_discovery_get_cathedral(&cathedral);

	resp.info.cathedral.id = t6->cs_id;
	resp.info.cathedral.last = cathedral.last;
	resp.info.cathedral.port = cathedral.addr.sin_port;
	resp.info.cathedral.ip = cathedral.addr.sin_addr.s_addr;

	if (sendto(fd, &resp, sizeof(resp), 0,
	    (const struct sockaddr *)peer, sizeof(*peer)) == -1)
		tier6_log(LOG_NOTICE, "ctl sendto: %s", errno_s);
}
