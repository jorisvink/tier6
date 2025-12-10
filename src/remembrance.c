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
#include <sys/stat.h>
#include <sys/socket.h>

#include <libkyrka/libnyfe.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

/* The currently loaded remembrances. */
static struct kyrka_event_remembrance	remembrances;

/*
 * Load the stored remembrances from disk into memory.
 */
void
tier6_remembrance_load(void)
{
	struct stat	st;
	ssize_t		ret;
	int		fd;

	PRECOND(t6->remembrance != NULL);

	fd = -1;
	memset(&remembrances, 0, sizeof(remembrances));

	if ((fd = open(t6->remembrance, O_RDONLY)) == -1) {
		if (errno != ENOENT) {
			tier6_log(LOG_NOTICE, "failed to open %s: %s",
			    t6->remembrance, errno_s);
		}
		goto cleanup;
	}

	if (fstat(fd, &st) == -1) {
		tier6_log(LOG_NOTICE, "stat(%s): %s", t6->remembrance, errno_s);
		goto cleanup;
	}

	if ((size_t)st.st_size != sizeof(remembrances)) {
		tier6_log(LOG_NOTICE, "remembrance has wrong size (%zu vs %zu)",
		    (size_t)st.st_size, sizeof(remembrances));
		goto cleanup;
	}

	for (;;) {
		ret = read(fd, &remembrances, sizeof(remembrances));
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("failed to read remembrances: %s", errno_s);
		}

		if ((size_t)ret != sizeof(remembrances)) {
			fatal("short read on remembrances %zd/%zu",
			    ret, sizeof(remembrances));
		}

		break;
	}

cleanup:
	if (fd != -1)
		(void)close(fd);
}

/*
 * Save the received remembrance and persist it on disk for restart later.
 */
void
tier6_remembrance_save(struct kyrka_event_remembrance *rem)
{
	ssize_t		ret;
	int		fd, len;
	char		tmp[1024];

	PRECOND(rem != NULL);
	PRECOND(t6->remembrance != NULL);

	if (!memcmp(&remembrances, rem, sizeof(*rem)))
		return;

	fd = -1;
	memcpy(&remembrances, rem, sizeof(*rem));

	len = snprintf(tmp, sizeof(tmp), "%s.tmp", t6->remembrance);
	if (len == -1 || (size_t)len >= sizeof(tmp))
		fatal("remembrance path '%s' too big", t6->remembrance);

	if (unlink(tmp) == -1 && errno != ENOENT) {
		tier6_log(LOG_NOTICE, "failed to unlink %s: %s", tmp, errno_s);
		return;
	}

	fd = open(tmp, O_CREAT | O_EXCL | O_TRUNC | O_WRONLY, 0600);
	if (fd == -1) {
		tier6_log(LOG_NOTICE, "failed to open %s: %s", tmp, errno_s);
		return;
	}

	for (;;) {
		if ((ret = write(fd, rem, sizeof(*rem))) == -1) {
			if (errno == EINTR)
				continue;
			tier6_log(LOG_NOTICE,
			    "write error on %s: %s", tmp, errno_s);
			goto cleanup;
		}

		if ((size_t)ret != sizeof(*rem)) {
			tier6_log(LOG_NOTICE, "short write on %s (%zd/%zu)",
			    tmp, ret, sizeof(*rem));
			goto cleanup;
		}

		break;
	}

	if (close(fd) == -1) {
		tier6_log(LOG_NOTICE, "failed to close %s: %s", tmp, errno_s);
		goto cleanup;
	}

	fd = -1;

	if (rename(tmp, t6->remembrance) == -1) {
		tier6_log(LOG_NOTICE, "failed to rename %s: %s", tmp, errno_s);
		(void)unlink(tmp);
	}

cleanup:
	if (fd != -1) {
		(void)close(fd);
		if (unlink(tmp) == -1) {
			tier6_log(LOG_NOTICE,
			    "failed to remove %s: %s", tmp, errno_s);
		}
	}
}

/*
 * Randomly select a new cathedral from our remembrance, if possible.
 */
int
tier6_remembrance_cathedral(struct tier6_cathedral *cat)
{
	u_int32_t		idx;
	int			count, attempts;

	PRECOND(cat != NULL);

	if (t6->remembrance == NULL)
		return (-1);

	count = 0;
	for (idx = 0; idx < KYRKA_CATHEDRALS_MAX; idx++) {
		if (remembrances.ips[idx] == 0 || remembrances.ports[idx] == 0)
			break;
		count++;
	}

	if (count == 0)
		return (-1);

	for (attempts = 0; attempts < KYRKA_CATHEDRALS_MAX; attempts++) {
		nyfe_random_bytes(&idx, sizeof(idx));
		idx = idx & (count - 1);
		if (cat->addr.sin_addr.s_addr != remembrances.ips[idx] ||
		    cat->addr.sin_port != remembrances.ports[idx])
			break;
	}

	if (attempts == KYRKA_CATHEDRALS_MAX)
		return (-1);

	cat->last = t6->now;
	cat->timeout = TIER6_CATHEDRAL_TIMEOUT_INIT;

	cat->addr.sin_port = remembrances.ports[idx];
	cat->addr.sin_addr.s_addr = remembrances.ips[idx];

	return (0);
}
