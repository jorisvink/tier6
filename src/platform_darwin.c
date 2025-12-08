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
#include <net/bpf.h>
#include <net/ndrv.h>
#include <netinet/if_ether.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tier6.h"

/*
 * Support for "tap" in MacOS does not exist but we can fake it via
 * the fake ethernet devices.
 *
 * It's a bit tricky though but we manage to make it work, it boils down to:
 *	1) Create 2 fake ethernet devices (feth6, feth666)
 *		feth6 will be the actual interface to use.
 *	2) Set them as peers of each other.
 *	3) Open a BPF interface and configure it to read feth666.
 *	4) Open an AF_NDRV socket and attach it to feth6.
 *
 * Now we can inject frames via feth6 and read frames from feth666.
 *
 * XXX - The feth device names and bpf interface are hardcoded.
 * XXX - We currently do not clean up interfaces.
 */

/* Hardcoded BPF interface we open. */
#define BPF_INTERFACE_NAME		"/dev/bpf99"

/* Hardcoded primary feth device. */
#define FETH_PRIMARY_IFC		"feth6"

/* Hardcoded peer feth device. */
#define FETH_PEER_IFC			"feth666"

/* The number of attempts at creating a feth interface before we give up. */
#define FETH_CREATION_TRIES_MAX		50

/*
 * Defined in xnu/bsd/net/if_fake_var.h, we need these to set
 * the actual peering.
 */
#define IF_FAKE_S_CMD_SET_PEER		1

struct if_fake_request {
	u_int64_t	iffr_reserved[4];

	union {
		char			iffru_buf[128];

		struct {
			int		iffm_current;
			u_int32_t	iffm_count;
			u_int32_t	iffm_reserved[3];
			int		iffm_list[27];
		} iffru_media;

		char			iffru_peer[IFNAMSIZ];
		u_int32_t		iffru_dequeue_stall;
	} iffr_u;
};

#define iffr_peer	iffr_u.iffru_peer

/*
 * MacOS does not export this ioctl, so we carry it here.
 * See bsd/sys/sockio_private.h in xnu.
 */
#define SIOCPROTOATTACH _IOWR('i', 80, struct ifreq)

/* The number of max events we handle in a single kevent() call. */
#define EVENTS_MAX			256

/* The number of bytes we can process in a single BPF read. */
#define BPF_READ_MAX_BYTES		8192

static void	darwin_feth_io(void *);
static void	darwin_feth_setup(void);
static void	darwin_bpf_open(const char *);
static void	darwin_ndrv_open(const char *);
static void	darwin_feth_lladdr(int, const char *);
static void	darwin_feth_create(int, const char *);
static void	darwin_ioctl(int, unsigned long, void *);

/* The kqueue() fd. */
static int		kfd = -1;

/* The io event interface. */
static struct tier6_io	feth_io;

/* We need two file descriptors for managing the fake ethernet devices. */
static int		bpf_fd = -1;
static int		ndrv_fd = -1;

/*
 * Initialise the Darwin platform.
 */
void
tier6_platform_init(void)
{
	PRECOND(kfd == -1);
	PRECOND(bpf_fd == -1);
	PRECOND(ndrv_fd == -1);

	if ((kfd = kqueue()) == -1)
		fatal("kqueue: %s", errno_s);

	darwin_feth_setup();

	tier6_log(LOG_INFO, "ignoring tapname '%s'", t6->tapname);
	tier6_log(LOG_INFO, "using feth device '%s'", FETH_PRIMARY_IFC);
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
 * Write a frame via our AF_NDRV interface.
 */
ssize_t
tier6_platform_tap_write(const void *data, size_t len)
{
	PRECOND(data != NULL);
	PRECOND(len > 0);

	return (write(ndrv_fd, data, len));
}

/*
 * Setup both fake ethernet interfaces, hook em up to each other
 * and configure everything in such a way that it should just work.
 */
void
darwin_feth_setup(void)
{
	int			fd;
	struct ifdrv		ifd;
	struct if_fake_request	iffr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&ifd, 0, sizeof(ifd));
	memset(&iffr, 0, sizeof(iffr));

	darwin_feth_create(fd, FETH_PRIMARY_IFC);
	darwin_feth_create(fd, FETH_PEER_IFC);
	darwin_feth_lladdr(fd, FETH_PRIMARY_IFC);

	(void)strlcpy(ifd.ifd_name, FETH_PRIMARY_IFC, sizeof(ifd.ifd_name));
	(void)strlcpy(iffr.iffr_peer, FETH_PEER_IFC, sizeof(iffr.iffr_peer));

	ifd.ifd_cmd = IF_FAKE_S_CMD_SET_PEER;
	ifd.ifd_len = sizeof(iffr);
	ifd.ifd_data = &iffr;

	darwin_ioctl(fd, SIOCSDRVSPEC, &ifd);
	close(fd);

	darwin_bpf_open(FETH_PEER_IFC);
	darwin_ndrv_open(FETH_PEER_IFC);

	tier6_socket_nonblock(bpf_fd);
	tier6_socket_nonblock(ndrv_fd);

	feth_io.handle = darwin_feth_io;
	tier6_platform_io_schedule(bpf_fd, &feth_io);
}

/*
 * Helper function to do an ioctl on a given socket.
 */
static void
darwin_ioctl(int fd, unsigned long ctl, void *data)
{
	PRECOND(fd >= 0);
	/* data may be NULL */

	if (ioctl(fd, ctl, data) == -1)
		fatal("ioctl(%lu): %s", ctl, errno_s);
}

/*
 * Helper function to create a fake ethernet instance.
 */
static void
darwin_feth_create(int fd, const char *ifc)
{
	struct ifreq		ifr;
	int			ret, tries;

	PRECOND(fd >= 0);
	PRECOND(ifc != NULL);

	memset(&ifr, 0, sizeof(ifr));

	if (strlcpy(ifr.ifr_name, ifc, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		fatal("feth name %s too large", ifc);

	for (tries = 0; tries < FETH_CREATION_TRIES_MAX; tries++) {
		if ((ret = ioctl(fd, SIOCIFCREATE2, &ifr)) == -1) {
			switch (errno) {
			case EEXIST:
				if (ioctl(fd, SIOCIFDESTROY, &ifr) == -1) {
					fatal("failed to destroy %s: %s",
					    ifc, errno_s);
				}
				break;
			case EBUSY:
				usleep(10000);
				break;
			default:
				fatal("SIOCIFCREATE2 %s: %s", ifc, errno_s);
			}
			continue;
		}

		break;
	}

	if (tries == FETH_CREATION_TRIES_MAX)
		fatal("failed to create feth %s", ifc);

	ifr.ifr_flags = IFF_UP | IFF_RUNNING;

	darwin_ioctl(fd, SIOCPROTOATTACH, &ifr);
	darwin_ioctl(fd, SIOCSIFFLAGS, &ifr);
}

/*
 * Set the given feth its lladdr.
 */
static void
darwin_feth_lladdr(int fd, const char *ifc)
{
	struct ifreq		ifr;

	PRECOND(fd >= 0);
	PRECOND(ifc != NULL);

	memset(&ifr, 0, sizeof(ifr));

	if (strlcpy(ifr.ifr_name, ifc, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		fatal("feth name %s too large", ifc);

	ifr.ifr_addr.sa_family = AF_LOCAL;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;

	ifr.ifr_addr.sa_data[0] = 0x06;
	ifr.ifr_addr.sa_data[1] = t6->kek_id;
	ifr.ifr_addr.sa_data[2] = (t6->cs_id >> 24) & 0xff;
	ifr.ifr_addr.sa_data[3] = (t6->cs_id >> 16) & 0xff;
	ifr.ifr_addr.sa_data[4] = (t6->cs_id >> 8) & 0xff;
	ifr.ifr_addr.sa_data[5] = t6->cs_id & 0xff;;

	darwin_ioctl(fd, SIOCSIFLLADDR, &ifr);
}

/*
 * Open and configure our BPF device to use the given interface.
 */
static void
darwin_bpf_open(const char *ifc)
{
	struct ifreq		ifr;
	int			len, val;

	PRECOND(ifc != NULL);

	memset(&ifr, 0, sizeof(ifr));

	if (strlcpy(ifr.ifr_name, ifc, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		fatal("feth name %s too large", ifc);

	if ((bpf_fd = open(BPF_INTERFACE_NAME, O_RDWR)) == -1)
		fatal("failed to open bpf99: %s", errno_s);

	len = BPF_READ_MAX_BYTES;
	darwin_ioctl(bpf_fd, BIOCSBLEN, &len);

	val = 1;
	darwin_ioctl(bpf_fd, BIOCIMMEDIATE, &val);
	darwin_ioctl(bpf_fd, BIOCSHDRCMPLT, &val);

	val = 0;
	darwin_ioctl(bpf_fd, BIOCSSEESENT, &val);

	darwin_ioctl(bpf_fd, BIOCSETIF, &ifr);
	darwin_ioctl(bpf_fd, BIOCPROMISC, NULL);
}

/*
 * Open an AF_NDRV socket and attach it to the given interface.
 */
static void
darwin_ndrv_open(const char *ifc)
{
	struct sockaddr_ndrv	ndr;

	PRECOND(ifc != NULL);

	memset(&ndr, 0, sizeof(ndr));

	if ((ndrv_fd = socket(AF_NDRV, SOCK_RAW, 0)) == -1)
		fatal("socket(AF_NDRV): %s", errno_s);

	ndr.snd_family = AF_NDRV;
	ndr.snd_len = sizeof(ndr);

	if (strlcpy((char *)ndr.snd_name, ifc, sizeof(ndr.snd_name)) >=
	    sizeof(ndr.snd_name))
		fatal("AF_NDRV snd_name %s too large", ifc);

	if (bind(ndrv_fd, (const struct sockaddr *)&ndr, sizeof(ndr)) == -1)
		fatal("bind: %s", errno_s);

	if (connect(ndrv_fd, (const struct sockaddr *)&ndr, sizeof(ndr)) == -1)
		fatal("bind: %s", errno_s);
}

/*
 * Read a frame from our BPF interface and inject them into peer tunnels.
 */
static void
darwin_feth_io(void *udata)
{
	ssize_t			ret;
	struct bpf_hdr		*hdr;
	u_int8_t		*ptr, *end, *data;
	u_int8_t		frame[BPF_READ_MAX_BYTES];

	PRECOND(bpf_fd >= 0);
	PRECOND(udata == &feth_io);

	for (;;) {
		if ((ret = read(bpf_fd, frame, sizeof(frame))) == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				feth_io.flags &= ~TIER6_IO_READABLE;
				return;
			}

			fatal("bpf read: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if ((size_t)ret < sizeof(*hdr))
			continue;

		ptr = frame;
		end = frame + ret;

		while (ptr < end) {
			hdr = (struct bpf_hdr *)ptr;

			if (hdr->bh_caplen <= sizeof(struct tier6_ether)) {
				ptr += BPF_WORDALIGN(hdr->bh_hdrlen +
				    hdr->bh_caplen);
				continue;
			}

			if ((ptr + hdr->bh_hdrlen + hdr->bh_caplen) <= ptr ||
			    (ptr + hdr->bh_hdrlen + hdr->bh_caplen) > end)
				fatal("bad bpf headers");

			data = ptr + hdr->bh_hdrlen;
			tier6_peer_output(data, hdr->bh_caplen);

			ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
		}
	}
}
