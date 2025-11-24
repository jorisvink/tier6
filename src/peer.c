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
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

/* The maximum age in seconds a MAC is valid. */
#define PEER_MAC_AGE_MAX	10

static void	peer_create(u_int8_t);
static void	peer_delete(u_int8_t);

static void	peer_io_event(void *);
static void	peer_io_read(struct tier6_peer *);

static void	peer_heartbeat(struct tier6_peer *);
static void	peer_mac_prune(struct tier6_peer *);
static int	peer_mac_forward(struct tier6_peer *, const u_int8_t *, size_t);
static void	peer_mac_register(struct tier6_peer *,
		    const struct tier6_ether *, int);

static void	peer_kyrka_event(KYRKA *, union kyrka_event *, void *);
static void	peer_kyrka_send(const void *, size_t, u_int64_t, void *);

static void	peer_heaven_input(const void *, size_t, u_int64_t, void *);
static void	peer_purgatory_input(const void *, size_t, u_int64_t, void *);

/* Our list of active peers. */
static LIST_HEAD(, tier6_peer)		peers;

/* The broadcast address is added to all tunnels. */
static struct tier6_ether		broadcast;

/* The next time we should update peers. */
static time_t				next_update;

/*
 * Initialise the peer subsystem.
 */
void
tier6_peer_init(void)
{
	LIST_INIT(&peers);

	memset(&broadcast, 0, sizeof(broadcast));

	broadcast.src[0] = 0xff;
	broadcast.src[1] = 0xff;
	broadcast.src[2] = 0xff;
	broadcast.src[3] = 0xff;
	broadcast.src[4] = 0xff;
	broadcast.src[5] = 0xff;
}

/*
 * Bring a peer up or down depending on the state given.
 */
void
tier6_peer_state(u_int8_t id, u_int8_t state)
{
	struct tier6_peer	*peer;

	PRECOND(id >= 1);

	if (state != 0 && state != 1) {
		tier6_log(LOG_NOTICE,
		    "[cathedral] sent wrong state (%u) for %02x", state, id);
		return;
	}

	LIST_FOREACH(peer, &peers, list) {
		if (peer->id == id)
			break;
	}

	if (peer == NULL && state == 1)
		peer_create(id);
	else if (peer != NULL && state == 0)
		peer_delete(id);
}

/*
 * Send a cathedral notification every 1 second for all alive peers.
 */
void
tier6_peer_update(void)
{
	struct tier6_peer	*peer;

	if (next_update > 0 && t6->now < next_update)
		return;

	next_update = t6->now + 1;

	LIST_FOREACH(peer, &peers, list) {
		if (kyrka_key_manage(peer->ctx) == -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_key_manage: %d",
			    peer->id, kyrka_last_error(peer->ctx));
		}

		if (kyrka_cathedral_notify(peer->ctx) == -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_cathedral_notify: %d",
			    peer->id, kyrka_last_error(peer->ctx));
		}

		if (kyrka_cathedral_nat_detection(peer->ctx) == -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_cathedral_nat_detection: %d",
			    peer->id, kyrka_last_error(peer->ctx));
		}

		peer_heartbeat(peer);
		peer_mac_prune(peer);
	}
}

/*
 * Forward an ethernet frame to the peers that should be getting it.
 *
 * Per peer we check if the destination MAC for the ethernet frame
 * was previously seen on it as a source MAC address.
 */
void
tier6_peer_output(const void *pkt, size_t len)
{
	const struct tier6_ether	*eth;
	struct tier6_peer		*peer;
	u_int16_t			proto;

	PRECOND(pkt != NULL);
	PRECOND(len >= sizeof(*eth));

	eth = pkt;

	proto = ntohs(eth->proto);

	switch (proto) {
	case TIER6_ETHER_TYPE_ARP:
	case TIER6_ETHER_TYPE_VLAN:
	case TIER6_ETHER_TYPE_IPV4:
	case TIER6_ETHER_TYPE_IPV6:
		break;
	default:
		tier6_log(LOG_NOTICE,
		    "[peer] ignoring unknown proto %04x", proto);
		return;
	}
	
	LIST_FOREACH(peer, &peers, list) {
		if (peer_mac_forward(peer, eth->dst, sizeof(eth->dst)) == -1)
			continue;

		if (kyrka_heaven_input(peer->ctx, pkt, len) == -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_heaven_input: %d",
			    peer->id, kyrka_last_error(peer->ctx));
		}
	}
}

/*
 * Create a new tunnel for the given peer and schedule it onto
 * our internal event loop.
 */
static void
peer_create(u_int8_t id)
{
	struct kyrka_cathedral_cfg	cfg;
	struct tier6_peer		*peer;

	PRECOND(id >= 1);

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		fatal("calloc: peer failed");

	LIST_INIT(&peer->macs);

	peer->id = id;
	peer->hb_frequency = 5;
	peer->io.handle = peer_io_event;

	peer_mac_register(peer, &broadcast, 1);

	memcpy(&peer->addr, &t6->cathedral, sizeof(t6->cathedral));
	memcpy(&peer->cathedral, &peer->addr, sizeof(peer->addr));

	if ((peer->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	tier6_socket_nonblock(peer->fd);
	tier6_platform_io_schedule(peer->fd, peer);

	if ((peer->ctx = kyrka_ctx_alloc(peer_kyrka_event, peer)) == NULL)
		fatal("failed to create peer context");

	memset(&cfg, 0, sizeof(cfg));

	cfg.identity = t6->cs_id;
	cfg.flock_src = t6->flock;
	cfg.flock_dst = t6->flock;
	cfg.tunnel = t6->kek_id << 8 | id;

	cfg.kek = t6->kek_path;
	cfg.cosk = t6->cosk_path;
	cfg.secret = t6->cs_path;

	cfg.udata = peer;
	cfg.send = peer_kyrka_send;

	if (kyrka_heaven_ifc(peer->ctx, peer_heaven_input, peer) == -1)
		fatal("kyrka_purgatory_ifc: %d", kyrka_last_error(peer->ctx));

	if (kyrka_purgatory_ifc(peer->ctx, peer_purgatory_input, peer) == -1)
		fatal("kyrka_purgatory_ifc: %d", kyrka_last_error(peer->ctx));

	if (kyrka_cathedral_config(peer->ctx, &cfg) == -1) {
		fatal("kyrka_cathedral_config: %d",
		    kyrka_last_error(peer->ctx));
	}

	LIST_INSERT_HEAD(&peers, peer, list);

	tier6_log(LOG_INFO, "[peer=%02x] tunnel created", id);
}

/*
 * Delete an existing tunnel for the given peer.
 */
static void
peer_delete(u_int8_t id)
{
	struct tier6_mac	*mac;
	struct tier6_peer	*peer;

	PRECOND(id >= 1);

	LIST_FOREACH(peer, &peers, list) {
		if (peer->id == id)
			break;
	}

	if (peer == NULL) {
		tier6_log(LOG_INFO,
		    "[peer=%02x] peer does not exist for removal", id);
		return;
	}

	while ((mac = LIST_FIRST(&peer->macs)) != NULL) {
		LIST_REMOVE(mac, list);
		free(mac);
	}

	LIST_REMOVE(peer, list);
	kyrka_ctx_free(peer->ctx);
	close(peer->fd);
	free(peer);

	tier6_log(LOG_INFO, "[peer=%02x] tunnel removed", id);
}

/*
 * Callback from our event loop when data is to be handled on the peer socket.
 */
static void
peer_io_event(void *udata)
{
	struct tier6_peer	*peer;

	PRECOND(udata != NULL);

	peer = udata;

	if (peer->io.flags & TIER6_IO_READABLE)
		peer_io_read(peer);
}

/*
 * Attempt to read packets from the peer socket and insert them into
 * the libkyrka context for handling.
 */
static void
peer_io_read(struct tier6_peer *peer)
{
	ssize_t		ret;
	u_int8_t	buf[1500];

	PRECOND(peer != NULL);

	for (;;) {
		if ((ret = read(peer->fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				peer->io.flags &= ~TIER6_IO_READABLE;
				break;
			}
			fatal("read: %s", errno_s);
		}

		if (ret == 0)
			continue;

		if (kyrka_purgatory_input(peer->ctx, buf, ret) == -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_purgatory_input: %d",
			    peer->id, kyrka_last_error(peer->ctx));
		}
	}
}

/*
 * Callback from libkyrka when an event occurred on the peer tunnel.
 */
static void
peer_kyrka_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	struct in_addr		in;
	struct tier6_peer	*peer;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	peer = udata;

	switch (evt->type) {
	case KYRKA_EVENT_KEYS_INFO:
		tier6_log(LOG_INFO, "[peer=%02x] tx=%08x rx=%08x",
		    peer->id, evt->keys.tx_spi, evt->keys.rx_spi);
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		tier6_log(LOG_INFO, "[peer=%02x] exchange: %s",
		    peer->id, evt->exchange.reason);
		break;
	case KYRKA_EVENT_AMBRY_RECEIVED:
		tier6_log(LOG_INFO, "[peer=%02x] ambry generation %08x",
		    peer->id, evt->ambry.generation);
		break;
	case KYRKA_EVENT_LOGMSG:
		tier6_log(LOG_INFO, "[peer=%02x] log: %s",
		    peer->id, evt->logmsg.log);
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		in.s_addr = evt->peer.ip;

		if (peer->addr.sin_addr.s_addr != evt->peer.ip ||
		    peer->addr.sin_port != evt->peer.port) {
			peer->addr.sin_port = evt->peer.port;
			peer->addr.sin_addr.s_addr = evt->peer.ip;

			if (peer->cathedral.sin_addr.s_addr !=
			    peer->addr.sin_addr.s_addr &&
			    peer->cathedral.sin_port !=
			    peer->addr.sin_port) {
				tier6_log(LOG_INFO,
				    "[peer=%02x] p2p discovery %s:%u",
				    peer->id, inet_ntoa(in),
				    htons(evt->peer.port));

				peer->hb_ticks = 15;
				peer->hb_frequency = 1;
			}
		}
		break;
	default:
		tier6_log(LOG_NOTICE, "[peer=%02x] unknown event %u",
		    peer->id, evt->type);
		break;
	}
}

/*
 * Callback from libkyrka when plaintext data is available. This plaintext
 * data should be an ethernet frame. We learn the source mac address and
 * output the frame onto our tap device.
 */
static void
peer_heaven_input(const void *data, size_t len, u_int64_t magic, void *udata)
{
	const struct tier6_ether	*eth;
	struct tier6_peer		*peer;
	u_int16_t			proto;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	peer = udata;

	if (len < sizeof(*eth))
		return;

	eth = data;
	proto = ntohs(eth->proto);

	switch (proto) {
	case TIER6_ETHER_TYPE_ARP:
	case TIER6_ETHER_TYPE_VLAN:
	case TIER6_ETHER_TYPE_IPV4:
	case TIER6_ETHER_TYPE_IPV6:
		break;
	default:
		return;
	}

	peer_mac_register(peer, eth, 0);
	tier6_tap_output(data, len);
}

/*
 * Callback from libkyrka when ciphertext is available. This ciphertext
 * is sent to the current known address for our peer.
 */
static void
peer_purgatory_input(const void *data, size_t len, u_int64_t magic, void *udata)
{
	struct tier6_peer	*peer;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	peer = udata;

	if (sendto(peer->fd, data, len, 0,
	    (const struct sockaddr *)&peer->addr, sizeof(peer->addr)) == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tier6_log(LOG_INFO,
			    "[peer=%02x] sendto: %s", peer->id, errno_s);
		}
	}
}

/*
 * Callback from libkyrka when ciphertext data is to be sent to our cathedral.
 */
static void
peer_kyrka_send(const void *data, size_t len, u_int64_t magic, void *udata)
{
	struct sockaddr_in	sin;
	u_int16_t		port;
	struct tier6_peer	*peer;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	peer = udata;

	port = be16toh(peer->cathedral.sin_port);
	if (magic == KYRKA_CATHEDRAL_NAT_MAGIC)
		port++;

	sin.sin_family = AF_INET;
	sin.sin_port = htobe16(port);
	sin.sin_addr.s_addr = peer->cathedral.sin_addr.s_addr;

	if (sendto(peer->fd, data, len, 0,
	    (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tier6_log(LOG_INFO,
			    "[peer=%02x] sendto: %s (cathedral)",
			    peer->id, errno_s);
		}
	}
}

/*
 * If needed send a heartbeat packet to our peer, this is mostly done
 * to keep any NAT states alive if we are in P2P mode.
 */
static void
peer_heartbeat(struct tier6_peer *peer)
{
	struct tier6_ether	eth;

	PRECOND(peer != NULL);

	if (peer->hb_next > 0 && t6->now < peer->hb_next)
		return;

	peer->hb_next = t6->now + peer->hb_frequency;

	if (peer->hb_ticks > 0) {
		peer->hb_ticks--;
		if (peer->hb_ticks == 0)
			peer->hb_frequency = 5;
	}

	memset(&eth, 0, sizeof(eth));
	eth.proto = htons(TIER6_ETHER_TYPE_HEARTBEAT);

	if (kyrka_heaven_input(peer->ctx, &eth, sizeof(eth)) == -1) {
		tier6_log(LOG_NOTICE, "[peer=%02x] kyrka_heaven_input: %d",
		    peer->id, kyrka_last_error(peer->ctx));
	}
}

/*
 * Register the given MAC address as seen on the peer, these eventually
 * expire unless `fixed` is set to 1.
 */
static void
peer_mac_register(struct tier6_peer *peer,
    const struct tier6_ether *eth, int fixed)
{
	struct tier6_mac	*mac;

	PRECOND(peer != NULL);
	PRECOND(eth != NULL);
	PRECOND(fixed == 0 || fixed == 1);

	LIST_FOREACH(mac, &peer->macs, list) {
		if (!memcmp(mac->addr, eth->src, TIER6_ETHERNET_MAC_LEN))
			break;
	}

	if (mac != NULL) {
		mac->age = t6->now;
		return;
	}

	if ((mac = calloc(1, sizeof(*mac))) == NULL)
		fatal("failed to allocate new ethernet mac address");

	mac->fixed = fixed;
	mac->age = t6->now;
	memcpy(mac->addr, eth->src, TIER6_ETHERNET_MAC_LEN);

	LIST_INSERT_HEAD(&peer->macs, mac, list);

	tier6_log(LOG_INFO,
	    "[peer=%02x] %02x:%02x:%02x:%02x:%02x:%02x disovered",
	    peer->id, mac->addr[0], mac->addr[1], mac->addr[2],
	    mac->addr[3], mac->addr[4], mac->addr[5]);
}

/*
 * Check if we should forward to a given peer based on the MAC address given.
 */
static int
peer_mac_forward(struct tier6_peer *peer, const u_int8_t *addr, size_t len)
{
	struct tier6_mac	*mac;

	PRECOND(peer != NULL);
	PRECOND(addr != NULL);
	PRECOND(len == TIER6_ETHERNET_MAC_LEN);

	if ((addr[0] & 0x01) == 1)
		return (0);

	LIST_FOREACH(mac, &peer->macs, list) {
		if (!memcmp(mac->addr, addr, len))
			break;
	}

	if (mac == NULL)
		return (-1);

	return (0);
}

/*
 * Prune all expired MAC addresses from the peer.
 */
static void
peer_mac_prune(struct tier6_peer *peer)
{
	struct tier6_mac	*mac, *next;

	PRECOND(peer != NULL);

	for (mac = LIST_FIRST(&peer->macs); mac != NULL; mac = next) {
		next = LIST_NEXT(mac, list);

		if (mac->fixed)
			continue;

		if ((t6->now - mac->age) >= PEER_MAC_AGE_MAX) {
			tier6_log(LOG_INFO,
			    "[peer=%02x] %02x:%02x:%02x:%02x:%02x:%02x gone",
			    peer->id, mac->addr[0], mac->addr[1], mac->addr[2],
			    mac->addr[3], mac->addr[4], mac->addr[5]);
			LIST_REMOVE(mac, list);
			free(mac);
		}
	}
}
