/*
 * Copyright (c) 2025-2026 Joris Vink <joris@sanctorum.se>
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
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/epoll.h>

#include <arpa/inet.h>

#include <net/if.h>

#include <linux/if_tun.h>
#include <linux/seccomp.h>
#include <linux/sockios.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tier6.h"
#include "seccomp.h"

/* Maximum number of events in one single epoll_wait() call. */
#define EVENTS_MAX	256

/* Default seccomp stuff. */
#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_AARCH64
#elif defined(__arm)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_ARM
#elif defined(__riscv)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_RISCV64
#else
#error "unsupported architecture"
#endif

#define SECCOMP_KILL_POLICY		SECCOMP_RET_KILL

static void		linux_tap_io(void *);
static void		linux_tap_create(void);
static void		linux_sandbox_seccomp(void);
static void		linux_bridge_configure(void);

/*
 * The seccomp bpf program its prologue.
 *
 * Verifies that the running architecture matches the one we're built for
 * and preps the system call number to be verified.
 */
static struct sock_filter filter_prologue[] = {
	KORE_BPF_LOAD(arch, 0),
	KORE_BPF_CMP(SECCOMP_AUDIT_ARCH, 1, 0),
	KORE_BPF_RET(SECCOMP_RET_KILL),
	KORE_BPF_LOAD(nr, 0),
};

/*
 * The seccomp bpf program its epilogue.
 *
 * This applies the selected seccomp policy if none of the system
 * calls matched the filters.
 */
static struct sock_filter filter_epilogue[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_KILL_POLICY)
};

/*
 * Our seccomp policy.
 */
static struct sock_filter tier6_seccomp_filter[] = {
	KORE_SYSCALL_ALLOW(epoll_ctl),
	KORE_SYSCALL_ALLOW(epoll_wait),
	KORE_SYSCALL_ALLOW(epoll_pwait),
	KORE_SYSCALL_ALLOW(epoll_pwait2),
	KORE_SYSCALL_ALLOW(epoll_create),
	KORE_SYSCALL_ALLOW(epoll_create1),

	KORE_SYSCALL_ALLOW(bind),
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(recvmsg),
	KORE_SYSCALL_ALLOW(recvfrom),
	KORE_SYSCALL_ALLOW(getsockname),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_INET),
	KORE_SYSCALL_ALLOW_ARG(socket, 0, AF_NETLINK),

	KORE_SYSCALL_ALLOW(unlink),
	KORE_SYSCALL_ALLOW(rename),

	KORE_SYSCALL_ALLOW(brk),
	KORE_SYSCALL_ALLOW(fstat),
	KORE_SYSCALL_ALLOW(fcntl),
	KORE_SYSCALL_ALLOW(open),
	KORE_SYSCALL_ALLOW(openat),
	KORE_SYSCALL_ALLOW(getpid),
	KORE_SYSCALL_ALLOW(getrandom),
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(clock_gettime),
	KORE_SYSCALL_ALLOW(rt_sigprocmask),
	KORE_SYSCALL_ALLOW(clock_nanosleep),
	KORE_SYSCALL_ALLOW(restart_syscall),

	KORE_SYSCALL_ALLOW_ARG(write, 0, STDOUT_FILENO),
};

/* The epoll fd use. */
static int		efd = -1;

/* The io event interface. */
static struct tier6_io	tap_io;

/* The tap fd. */
static int		tap_fd = -1;

/* Is seccomp tracing enabled or not? */
int			linux_seccomp_tracing = 0;

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

	if (t6->bridge != NULL)
		linux_bridge_configure();

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
	linux_sandbox_seccomp();
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
 * Configure the tap interface.
 */
void
tier6_platform_tap_configure(struct in_addr *addr)
{
	struct ifreq		ifr;
	struct sockaddr_in	sin;
	int			fd, len;

	PRECOND(addr != NULL);

	memset(&ifr, 0, sizeof(ifr));

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", t6->tapname);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("tap interface name '%s' too large", t6->tapname);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

	memcpy(&sin.sin_addr, addr, sizeof(*addr));
	memcpy(&ifr.ifr_addr, &sin, sizeof(sin));

	if (ioctl(fd, SIOCSIFADDR, &ifr) == -1)
		fatal("ioctl(SIOCSIFADDR): %s", errno_s);

	sin.sin_addr.s_addr = htonl(0xffffff00);
	memcpy(&ifr.ifr_addr, &sin, sizeof(sin));

	if (ioctl(fd, SIOCSIFNETMASK, &ifr) == -1)
		fatal("ioctl(SIOCSIFNETMASK): %s", errno_s);

	(void)close(fd);
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

	ifr.ifr_mtu = t6->mtu;

	if (ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
		fatal("failed to set mtu (%u) on tap device %s: %s",
		    t6->mtu, t6->tapname, errno_s);
	}

	(void)close(fd);

	tier6_log(LOG_INFO, "interface '%s' created", t6->tapname);
}

/*
 * Create and (or) join the configured bridge interface.
 */
static void
linux_bridge_configure(void)
{
	struct ifreq		ifr;
	int			fd, len;

	PRECOND(t6->bridge != NULL);

	memset(&ifr, 0, sizeof(ifr));

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", t6->bridge);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("bridge name '%s' too long", t6->bridge);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	if (ioctl(fd, SIOCBRADDBR, ifr.ifr_name) == -1) {
		if (errno != EEXIST)
			fatal("ioctl(SIOCBRADDBR): %s", errno_s);
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	ifr.ifr_ifindex = if_nametoindex(t6->tapname);
	if (ioctl(fd, SIOCBRADDIF, &ifr) == -1)
		fatal("ioctl(SIOCBRADDIF): %s", errno_s);

	(void)close(fd);

	tier6_log(LOG_INFO, "added '%s' to '%s'", t6->tapname, t6->bridge);
}

/*
 * Read a frame from our tap interface and inject it into peer tunnels.
 */
static void
linux_tap_io(void *udata)
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

/*
 * Apply our seccomp rules to our tier6 process.
 */
static void
linux_sandbox_seccomp(void)
{
	struct sock_filter		*sf;
	struct sock_fprog		prog;
	size_t				len, idx, off;

	/* If tracing is enabled, change the policy to SECCOMP_RET_LOG. */
	if (linux_seccomp_tracing) {
		filter_epilogue[0].k = SECCOMP_RET_LOG;
		tier6_log(LOG_INFO, "seccomping is logging");
	}

	len = KORE_FILTER_LEN(filter_prologue) +
	    KORE_FILTER_LEN(tier6_seccomp_filter) +
	    KORE_FILTER_LEN(filter_epilogue);

	if ((sf = calloc(len, sizeof(*sf))) == NULL)
		fatal("calloc(%zu): %s", len, errno_s);

	off = 0;

	for (idx = 0; idx < KORE_FILTER_LEN(filter_prologue); idx++)
		sf[off++] = filter_prologue[idx];

	for (idx = 0; idx < KORE_FILTER_LEN(tier6_seccomp_filter); idx++)
		sf[off++] = tier6_seccomp_filter[idx];

	for (idx = 0; idx < KORE_FILTER_LEN(filter_epilogue); idx++)
		sf[off++] = filter_epilogue[idx];

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal("prctl(privs): %s", errno_s);

	prog.len = len;
	prog.filter = sf;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		fatal("prctl(seccomp): %s", errno_s);
}
