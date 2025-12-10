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
#include <sys/socket.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <limits.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "tier6.h"

/*
 * To condense configuration a little bit tier6 supports reliquary
 * paths out of the box for cs-path, cosk-path and kek-path.
 */
#define CONFIG_RELIQUARY_PATH	"%s/.config/reliquary/%" PRIx64

static void	config_check_file(const char *);

static void	config_parse_runas(char *);
static void	config_parse_flock(char *);
static void	config_parse_cs_id(char *);
static void	config_parse_kek_id(char *);
static void	config_parse_tapname(char *);
static void	config_parse_cs_path(char *);
static void	config_parse_kek_path(char *);
static void	config_parse_cosk_path(char *);
static void	config_parse_cathedral(char *);
static void	config_parse_remembrance(char *);
static void	config_build_default_paths(void);

static char	*config_read_line(FILE *, char *, size_t);

static struct {
	const char	*name;
	void		(*parse)(char *);
} opts[] = {
	{ "cs-id",		config_parse_cs_id },
	{ "cs-path",		config_parse_cs_path },
	{ "cosk-path",		config_parse_cosk_path },

	{ "kek-id",		config_parse_kek_id },
	{ "kek-path",		config_parse_kek_path },

	{ "runas",		config_parse_runas },
	{ "flock",		config_parse_flock },
	{ "tapname",		config_parse_tapname },
	{ "cathedral",		config_parse_cathedral },
	{ "remembrance",	config_parse_remembrance },

	{ NULL, NULL },
};

/*
 * Parse our configuration file, setting up everything we need
 * in our global context so we can get up and running.
 */
void
tier6_config(const char *path)
{
	FILE		*fp;
	int		idx;
	char		buf[128], *line, *opt;

	PRECOND(path != NULL);

	if ((fp = fopen(path, "r")) == NULL)
		fatal("failed to open configuration file '%s'", path);

	for (;;) {
		if ((line = config_read_line(fp, buf, sizeof(buf))) == NULL)
			break;

		if (line[0] == '#' || strlen(line) == 0)
			continue;

		if ((opt = strchr(line, ' ')) == NULL)
			fatal("option '%s' is missing a value", line);

		*(opt)++ = '\0';

		while (isspace((unsigned char)*opt))
			opt++;

		for (idx = 0; opts[idx].name != NULL; idx++) {
			if (!strcmp(opts[idx].name, line))
				break;
		}

		if (opts[idx].name == NULL)
			fatal("unknown option '%s'", line);

		opts[idx].parse(opt);
	}

	fclose(fp);

	if (t6->cs_id == 0)
		fatal("no cs-id was specified in the configuration");

	if (t6->kek_id == 0)
		fatal("no kek-id was specified in the configuration");

	if (t6->flock == 0)
		fatal("no flock was specified in the configuration");

	if (t6->cathedral.addr.sin_addr.s_addr == 0)
		fatal("no cathedral was specified in the configuration");

	if (t6->runas == NULL)
		fatal("no runas was specified in the configuration");

	if (t6->tapname == NULL)
		fatal("no tapname was specified in the configuration");

	if (t6->cs_path == NULL || t6->kek_path == NULL ||
	    t6->cosk_path == NULL)
		config_build_default_paths();

	if (t6->cs_path == NULL)
		fatal("no cs-path was specified in the configuration");

	if (t6->kek_path == NULL)
		fatal("no kek-path was specified in the configuration");

	if (t6->cosk_path == NULL)
		fatal("no cosk-path was specified in the configuration");
}

/*
 * Helper function to read a single line from our configuration. We skip
 * the initial whitespaces and return a pointer to the first non-whitespace
 * character to the caller.
 */
static char *
config_read_line(FILE *fp, char *buf, size_t buflen)
{
	char		*ptr;

	PRECOND(fp != NULL);
	PRECOND(buf != NULL);
	PRECOND(buflen > 0 && buflen < INT_MAX);

	if (fgets(buf, buflen, fp) == NULL) {
		if (feof(fp))
			return (NULL);
		fatal("an error occurred reading configuration");
	}

	buf[strcspn(buf, "\n")] = '\0';

	ptr = buf;

	while (isspace((unsigned char)*ptr))
		ptr++;

	return (ptr);
}

/*
 * Parse the cs-id configuration option.
 */
static void
config_parse_cs_id(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%08x", &t6->cs_id) != 1)
		fatal("cs-id <hex> (32-bit number)");
}

/*
 * Parse the kek-id configuration option.
 */
static void
config_parse_kek_id(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%hhx", &t6->kek_id) != 1)
		fatal("kek-id <hex> (8-bit number)");
}

/*
 * Parse the runas configuration option.
 */
static void
config_parse_runas(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->runas != NULL)
		fatal("runas already specified");

	if ((t6->runas = strdup(opt)) == NULL)
		fatal("strdup");
}

/*
 * Parse the flock configuration option.
 */
static void
config_parse_flock(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%" PRIx64, &t6->flock) != 1)
		fatal("flock <hex> (64-bit number)");
}

/*
 * Parse the tapname configuration option.
 */
static void
config_parse_tapname(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->tapname != NULL)
		fatal("tapname already specified");

	if ((t6->tapname = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the cs-path configuration option.
 */
static void
config_parse_cs_path(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->cs_path != NULL)
		fatal("cs-path already specified");

	config_check_file(opt);

	if ((t6->cs_path = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the kek-path configuration option.
 */
static void
config_parse_kek_path(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->kek_path != NULL)
		fatal("kek-path already specified");

	config_check_file(opt);

	if ((t6->kek_path = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the cosk-path configuration option.
 */
static void
config_parse_cosk_path(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->cosk_path != NULL)
		fatal("cosk-path already specified");

	config_check_file(opt);

	if ((t6->cosk_path = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the cathedral configuration option.
 */
static void
config_parse_cathedral(char *opt)
{
	char		*port;

	PRECOND(opt != NULL);

	if ((port = strchr(opt, ':')) == NULL)
		fatal("cathedral <ip:port>");

	*(port)++ = '\0';

	if (sscanf(port, "%hu", &t6->cathedral.addr.sin_port) != 1)
		fatal("cathedral <ip:port>, port '%s' invalid", port);

	if (inet_pton(AF_INET, opt, &t6->cathedral.addr.sin_addr.s_addr) == -1)
		fatal("cathedral <ip:port>, ip '%s' invalid", opt);

	t6->cathedral.last = 0;
	t6->cathedral.addr.sin_family = AF_INET;
	t6->cathedral.addr.sin_port = htons(t6->cathedral.addr.sin_port);
}

/*
 * Parse the remembrance configuration option.
 */
static void
config_parse_remembrance(char *opt)
{
	PRECOND(opt != NULL);

	if (t6->remembrance != NULL)
		fatal("remembrance already specified");

	if ((t6->remembrance = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Helper function to check read-access to the given path.
 */
static void
config_check_file(const char *path)
{
	PRECOND(path != NULL);

	if (access(path, R_OK) == -1)
		fatal("%s is not readable (%s)", path, errno_s);
}

/*
 * Generate default paths for cosk, cs, and kek if they are missing.
 * This will match the default structure used by reliquary and allows for
 * smaller config files.
 */
void
config_build_default_paths(void)
{
	int			len;
	struct passwd 		*pw;
	u_int64_t		flock;
	char			path[4096];

	PRECOND(t6 != NULL);
	PRECOND(t6->flock != 0);
	PRECOND(t6->cs_id != 0);
	PRECOND(t6->kek_id != 0);
	PRECOND(t6->runas != NULL);

	if ((pw = getpwnam(t6->runas)) == NULL) {
		fatal("failed to get home dir path of runas user <%s>",
		    t6->runas);
	}

	flock = t6->flock & ~(0xff);

	if (t6->cs_path == NULL) {
		len = snprintf(path, sizeof(path),
		    CONFIG_RELIQUARY_PATH "/id-%08x",
		    pw->pw_dir, flock, t6->cs_id);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("failed to create cs_path");

		if ((t6->cs_path = strdup(path)) == NULL)
			fatal("strdup");

		tier6_log(LOG_INFO, "loading cs-id from default path");
	}

	if (t6->cosk_path == NULL) {
		len = snprintf(path, sizeof(path),
		    CONFIG_RELIQUARY_PATH "/cosk-%08x",
		    pw->pw_dir, flock, t6->cs_id);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("failed to create cs_path");

		if ((t6->cosk_path = strdup(path)) == NULL)
			fatal("strdup");

		tier6_log(LOG_INFO, "loading cosk from default path");
	}

	if (t6->kek_path == NULL) {
		len = snprintf(path, sizeof(path),
		    CONFIG_RELIQUARY_PATH "/kek-0x%02x",
		    pw->pw_dir, flock, t6->kek_id);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("failed to create cs_path");

		if ((t6->kek_path = strdup(path)) == NULL)
			fatal("strdup");

		tier6_log(LOG_INFO, "loading kek from default path");
	}
}
