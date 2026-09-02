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

#ifndef __H_TIER6_CTL_H
#define __H_TIER6_CTL_H

/* Request list of current peers. */
#define TIER6_CTL_REQUEST_PEERS		1

/* Request information about the tier6 instance. */
#define TIER6_CTL_REQUEST_INFO		2

/*
 * A control request that can be sent to tier6.
 */
struct tier6_ctl_request {
	u_int16_t		type;
} __attribute__((packed));

/*
 * Statistics for a "peer" or "cathedral".
 */
struct tier6_ctl_stats {
	u_int32_t	id;
	u_int32_t	ip;
	u_int16_t	port;
	time_t		last;
	u_int64_t	tx_bytes;
	u_int64_t	rx_bytes;
};

/*
 * A single peer for a TIER6_CTL_REQUEST_PEER_LIST response.
 * These are sent one by one to the requester, with a last
 * response being indicated by state being set to 0.
 */
struct tier6_ctl_peer {
	u_int16_t			state;
	struct tier6_ctl_stats		peer;
	struct tier6_ctl_stats		cathedral;
};

/*
 * A TIER6_CTL_REQUEST_INFO response.
 */
struct tier6_ctl_info {
	u_int64_t			flock;
	u_int32_t			cs_id;
	u_int8_t			kek_id;

	struct tier6_ctl_stats		cathedral;
};

/*
 * The response data structure sent back, which data struct to use
 * depends on what the request sent was.
 */
union tier6_ctl_response {
	struct tier6_ctl_info		info;
};

#endif
