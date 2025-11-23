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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

static void	peer_create(u_int8_t);
static void	peer_delete(u_int8_t);

static void	peer_io_event(void *);
static void	peer_io_read(struct tier6_peer *);

static void	peer_mac_prune(struct tier6_peer *);
static int	peer_mac_check(struct tier6_peer *, const u_int8_t *, size_t);
static void	peer_mac_register(struct tier6_peer *,
		    const struct tier6_ether *, int);

static void	peer_kyrka_event(KYRKA *, union kyrka_event *, void *);
static void	peer_kyrka_send(const void *, size_t, u_int64_t, void *);

static void	peer_heaven_input(const void *, size_t, u_int64_t, void *);
static void	peer_purgatory_input(const void *, size_t, u_int64_t, void *);

static LIST_HEAD(, tier6_peer)		peers;
static struct tier6_ether		broadcast;
static time_t				next_update;

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

void
tier6_peer_state(u_int8_t id, u_int8_t state)
{
	struct tier6_peer	*peer;

	PRECOND(id >= 1);

	if (state != 0 && state != 1) {
		printf("upstream sent wrong state (%u) for %02x\n", state, id);
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

void
tier6_peer_update(void)
{
	struct tier6_peer	*peer;

	if (next_update > 0 && t6->now < next_update)
		return;

	next_update = t6->now + 1;

	LIST_FOREACH(peer, &peers, list) {
		if (kyrka_key_manage(peer->ctx) == -1) {
			printf("kyrka_key_manage: %d\n",
			    kyrka_last_error(peer->ctx));
		}

		if (kyrka_cathedral_notify(peer->ctx) == -1) {
			printf("kyrka_cathedral_notify: %d\n",
			    kyrka_last_error(peer->ctx));
		}

		if (kyrka_cathedral_nat_detection(peer->ctx) == -1) {
			printf("kyrka_cathedral_nat_detection: %d\n",
			    kyrka_last_error(peer->ctx));
		}

		peer_mac_prune(peer);
	}
}

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
		printf("ignoring unknown proto %04x\n", proto);
		return;
	}
	
	LIST_FOREACH(peer, &peers, list) {
		if (peer_mac_check(peer, eth->dst, sizeof(eth->dst)) == -1)
			continue;

		if (kyrka_heaven_input(peer->ctx, pkt, len) == -1) {
			printf("kyrka_heaven_input: %d\n",
			    kyrka_last_error(peer->ctx));
		}
	}
}

static void
peer_create(u_int8_t id)
{
	struct kyrka_cathedral_cfg	cfg;
	struct tier6_peer		*peer;

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		fatal("calloc: peer failed");

	LIST_INIT(&peer->macs);

	peer->id = id;
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
	printf("peer %02x created\n", id);
}

static void
peer_delete(u_int8_t id)
{
	struct tier6_mac	*mac;
	struct tier6_peer	*peer;

	LIST_FOREACH(peer, &peers, list) {
		if (peer->id == id)
			break;
	}

	if (peer == NULL) {
		printf("peer %02x does not exist\n", id);
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

	printf("peer %02x removed\n", id);
}

static void
peer_io_event(void *udata)
{
	struct tier6_peer	*peer;

	PRECOND(udata != NULL);

	peer = udata;

	if (peer->io.flags & TIER6_IO_READABLE)
		peer_io_read(peer);
}

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
			printf("kyrka_purgatory_input: %d\n",
			    kyrka_last_error(peer->ctx));
		}
	}
}

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
		printf("%02x tx=%08x rx=%08x\n",
		    peer->id, evt->keys.tx_spi, evt->keys.rx_spi);
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		printf("%02x exchange: %s\n", peer->id, evt->exchange.reason);
		break;
	case KYRKA_EVENT_AMBRY_RECEIVED:
		printf("%02x ambry generation %08x\n",
		    peer->id, evt->ambry.generation);
		break;
	case KYRKA_EVENT_LOGMSG:
		printf("%02x log %s\n", peer->id, evt->logmsg.log);
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
				printf("%02x p2p discovery %s:%u", peer->id,
				    inet_ntoa(in), htons(evt->peer.port));
			}
		}
		break;
	default:
		printf("%02x event %u\n", peer->id, evt->type);
		break;
	}
}

static void
peer_heaven_input(const void *data, size_t len, u_int64_t magic, void *udata)
{
	const struct tier6_ether	*eth;
	struct tier6_peer		*peer;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	peer = udata;

	if (len < sizeof(*eth))
		return;

	eth = data;

	peer_mac_register(peer, eth, 0);
	tier6_tap_output(data, len);
}

static void
peer_purgatory_input(const void *data, size_t len, u_int64_t magic, void *udata)
{
	struct tier6_peer	*peer;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	peer = udata;

	if (sendto(peer->fd, data, len, 0,
	    (const struct sockaddr *)&peer->addr, sizeof(peer->addr)) == -1)
		printf("sendto: %s\n", errno_s);
}

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
	    (struct sockaddr *)&sin, sizeof(sin)) == -1)
		printf("sendto: %s\n", errno_s);
}

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

	printf("%02x:%02x:%02x:%02x:%02x:%02x disovered on %02x\n",
	    mac->addr[0], mac->addr[1], mac->addr[2],
	    mac->addr[3], mac->addr[4], mac->addr[5], peer->id);
}

static int
peer_mac_check(struct tier6_peer *peer, const u_int8_t *addr, size_t len)
{
	struct tier6_mac	*mac;

	PRECOND(peer != NULL);
	PRECOND(addr != NULL);
	PRECOND(len == TIER6_ETHERNET_MAC_LEN);

	LIST_FOREACH(mac, &peer->macs, list) {
		if (!memcmp(mac->addr, addr, len))
			break;
	}

	if (mac == NULL)
		return (-1);

	return (0);
}

static void
peer_mac_prune(struct tier6_peer *peer)
{
	struct tier6_mac	*mac, *next;

	PRECOND(peer != NULL);

	for (mac = LIST_FIRST(&peer->macs); mac != NULL; mac = next) {
		next = LIST_NEXT(mac, list);

		if (mac->fixed)
			continue;

		if ((t6->now - mac->age) >= 10) {
			printf("%02x:%02x:%02x:%02x:%02x:%02x gone on %02x\n",
			    mac->addr[0], mac->addr[1], mac->addr[2],
			    mac->addr[3], mac->addr[4], mac->addr[5],
			    peer->id);
			LIST_REMOVE(mac, list);
			free(mac);
		}
	}
}
