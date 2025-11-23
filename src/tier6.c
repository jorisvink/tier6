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
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "tier6.h"

static void	usage(void) __attribute__((noreturn));
static void	version(void) __attribute__((noreturn));

static void	signal_trap(int);
static void	signal_hdlr(int);
static void	signal_memfault(int);

/* The global tier6 state. */
struct tier6			*t6;

/* The last received signal. */
static volatile sig_atomic_t	sig_recv = -1;

/* Are we running in foreground mode or not. */
static int			foreground = 1;

/*
 * Show tier6 usage.
 */
static void
usage(void)
{
	printf("tier6 [-d] [config]\n");
	printf("\n");
	printf("options:\n");
	printf("  -d  Daemonize the process, running in the background.\n");
	printf("  -h  This help text.\n");
	exit(1);
}

/*
 * Show tier6 version.
 */
static void
version(void)
{
	printf("tier6 %s (%s)\n", tier6_build_rev, tier6_build_date);
	exit(1);
}

/*
 * tier6 startup, gets everything going.
 */
int
main(int argc, char **argv)
{
	struct timespec		ts;
	sigset_t		sigset;
	int			ch, running;

	while ((ch = getopt(argc, argv, "dhv")) != -1) {
		switch (ch) {
		case 'd':
			foreground = 0;
			break;
		case 'v':
			version();
			break;
		case 'h':
			/* FALLTHROUGH */
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	if ((t6 = calloc(1, sizeof(*t6))) == NULL)
		fatal("failed to allocate t6 context");

	signal_trap(SIGINT);
	signal_trap(SIGHUP);
	signal_trap(SIGQUIT);
	signal_trap(SIGTERM);
	signal_trap(SIGSEGV);

	tier6_config(argv[0]);
	tier6_platform_init();

	tier6_tap_init();
	tier6_peer_init();
	tier6_discovery_init();

	if (foreground == 0) {
		openlog("tier6", LOG_NDELAY | LOG_PID, LOG_DAEMON);
		if (daemon(1, 0) == -1)
			fatal("daemon: %s", errno_s);
	}

	if (sigfillset(&sigset) == -1)
		fatal("sigfillset: %s", errno_s);

	sigdelset(&sigset, SIGINT);
	sigdelset(&sigset, SIGHUP);
	sigdelset(&sigset, SIGQUIT);
	sigdelset(&sigset, SIGTERM);
	(void)sigprocmask(SIG_BLOCK, &sigset, NULL);

	tzset();
	tier6_platform_sandbox();

	running = 1;
	tier6_log(LOG_INFO, "up and running");

	while (running) {
		if (sig_recv != -1) {
			tier6_log(LOG_INFO, "received signal %d", sig_recv);
			switch (sig_recv) {
			case SIGINT:
			case SIGHUP:
			case SIGQUIT:
			case SIGTERM:
				running = 0;
				continue;
			}
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		t6->now = ts.tv_sec;

		tier6_platform_io_wait();
		tier6_peer_update();
		tier6_discovery_update();
	}

	tier6_log(LOG_INFO, "shutting down");

	return (0);
}

/*
 * Drop privileges to the configured runas user.
 */
void
tier6_drop_user(void)
{
	struct passwd		*pw;

	PRECOND(t6->runas != NULL);

	if ((pw = getpwnam(t6->runas)) == NULL)
		fatal("failed to find runas '%s' (%s)", t6->runas, errno_s);

	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setgid(pw->pw_gid) == -1 || setegid(pw->pw_gid) == -1 ||
	    setuid(pw->pw_uid) == -1 || seteuid(pw->pw_uid) == -1)
		fatal("failed to drop privileges (%s)", errno_s);
}

/*
 * Log a message to either stdout or syslog().
 */
void
tier6_log(int prio, const char *fmt, ...)
{
	va_list		args;

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	va_start(args, fmt);
	tier6_logv(prio, fmt, args);
	va_end(args);
}

/*
 * Log a message to either stdout or syslog(), the variadic variant.
 */
void
tier6_logv(int prio, const char *fmt, va_list args)
{
	struct tm		*t;
	struct timespec		ts;
	char			tbuf[32];

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	if (foreground == 0) {
		vsyslog(prio, fmt, args);
	} else {
		(void)clock_gettime(CLOCK_REALTIME, &ts);
		t = gmtime(&ts.tv_sec);

		if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", t) > 0)
			printf("%s.%03ld UTC ", tbuf, ts.tv_nsec / 1000000);

		printf("[tier6] ");
		vprintf(fmt, args);
		printf("\n");
		fflush(stdout);
	}
}

/*
 * Helper function to mark a given fd as non-blocking.
 */
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

/* Bad juju happened. */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	kyrka_emergency_erase();

	va_start(args, fmt);
	tier6_logv(LOG_ERR, fmt, args);
	va_end(args);

	exit(1);
}

/*
 * Let the given signal be caught by our signal handler.
 */
static void
signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));

	if (sig == SIGSEGV)
		sa.sa_handler = signal_memfault;
	else
		sa.sa_handler = signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Our signal handler, doesn't do much.
 */
static void
signal_hdlr(int sig)
{
	sig_recv = sig;
}

/*
 * Our SIGSEGV signal handler, the best thing we can do here is give up
 * quick and hard to avoid keeping secrets in memory.
 */
static void
signal_memfault(int sig)
{
	kyrka_emergency_erase();
	abort();
}
