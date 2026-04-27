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
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <net/if.h>

#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tier6.h"

/* The maximum age in seconds a MAC is valid. */
#define PEER_MAC_AGE_MAX	((60 * 20) * 1000)

/* The age in seconds before we consider a peer timed out. */
#define PEER_ALIVE_TIMEOUT	(45 * 1000)

static void	peer_create(u_int8_t);
static void	peer_delete(struct tier6_peer *);

static void	peer_io_event(void *);
static void	peer_io_read(struct tier6_peer *);

static void	peer_heartbeat_send(struct tier6_peer *);
static void	peer_heartbeat_recv(struct tier6_peer *, struct kyrka_packet *);

static void	peer_discovery_ack(struct tier6_peer *);
static void	peer_discovery_probe(struct tier6_peer *, u_int32_t, u_int16_t);

static void	peer_mac_prune(struct tier6_peer *);
static void	peer_cathedral_alive(struct tier6_peer *);
static void	peer_cathedral_check(struct tier6_peer *);
static int	peer_mac_forward(struct tier6_peer *, const u_int8_t *, size_t);
static void	peer_mac_register(struct tier6_peer *,
		    const struct tier6_ether *, int);

static void	peer_kyrka_event(KYRKA *, union kyrka_event *, void *);
static void	peer_kyrka_send(struct kyrka_packet *, u_int64_t, void *);

static void	peer_heaven_input(struct kyrka_packet *, u_int64_t, void *);
static void	peer_purgatory_input(struct kyrka_packet *, u_int64_t, void *);

/* Our list of active peers. */
static LIST_HEAD(, tier6_peer)		peers;

/* The sender of our current received packet. */
static struct sockaddr_in		sender;

/* The next time we should update all peers. */
static time_t				next_update;

/*
 * Initialise the peer subsystem.
 */
void
tier6_peer_init(void)
{
	LIST_INIT(&peers);
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
		peer_delete(peer);
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

	next_update = t6->now + 1000;

	LIST_FOREACH(peer, &peers, list) {
		if (t6->remembrance != NULL)
			peer_cathedral_check(peer);

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

		peer_heartbeat_send(peer);
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
tier6_peer_output(const void *frame, size_t len)
{
	struct kyrka_packet		pkt;
	const struct tier6_ether	*eth;
	u_int8_t			*ptr;
	struct tier6_peer		*peer;
	u_int16_t			proto;
	size_t				maxlen;

	PRECOND(frame != NULL);
	PRECOND(len >= sizeof(*eth));

	eth = frame;

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

		ptr = kyrka_packet_databuf(peer->ctx, &pkt, &maxlen);
		if (ptr == NULL)
			fatal("failed to get peer data buffer");

		if (len > maxlen) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] frame of %zu too large (max:%zu)",
			    peer->id, len, maxlen);
			continue;
		}

		memcpy(ptr, frame, len);
		pkt.length = len;

		if (tier6_inet_match(&peer->addr, &peer->cathedral.addr))
			pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;
		else
			pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

		if (kyrka_heaven_input(peer->ctx, &pkt) == -1 &&
		    kyrka_last_error(peer->ctx) != KYRKA_ERROR_NO_TX_KEY) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] kyrka_heaven_input: %d (%zu)",
			    peer->id, kyrka_last_error(peer->ctx), len);
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
	struct sockaddr_in		sin;
	struct tier6_peer		*peer;
	socklen_t			socklen;

	PRECOND(id >= 1);

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		fatal("calloc: peer failed");

	LIST_INIT(&peer->macs);

	peer->id = id;
	peer->hb_frequency = 5000;
	peer->io.handle = peer_io_event;

	if ((peer->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

	if (bind(peer->fd, (const struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("bind: %s", errno_s);

	socklen = sizeof(sin);
	if (getsockname(peer->fd, (struct sockaddr *)&sin, &socklen) == -1)
		fatal("getsockname: %s", errno_s);

	peer->port = sin.sin_port;

	tier6_socket_nonblock(peer->fd);
	tier6_platform_io_schedule(peer->fd, peer);

	if ((peer->ctx = kyrka_ctx_alloc(peer_kyrka_event, peer)) == NULL)
		fatal("failed to create peer context");

	memset(&cfg, 0, sizeof(cfg));

	if (t6->remembrance != NULL) {
		cfg.remembrance = 1;
		if (tier6_remembrance_cathedral(&peer->cathedral) == -1) {
			memcpy(&peer->cathedral, &t6->cathedral,
			    sizeof(t6->cathedral));
		}
	} else {
		memcpy(&peer->cathedral, &t6->cathedral, sizeof(t6->cathedral));
	}

	memcpy(&peer->addr, &peer->cathedral.addr,
	    sizeof(peer->cathedral.addr));

	peer->cathedral.last = t6->now;
	peer->cathedral.timeout = TIER6_CATHEDRAL_TIMEOUT_INIT;

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

	if (t6->flags & TIER6_FLAG_SHROUD) {
		if (kyrka_shroud_enable(peer->ctx) == -1) {
			fatal("failed to enable shroud: %d",
			    kyrka_last_error(peer->ctx));
		}
	}

	LIST_INSERT_HEAD(&peers, peer, list);

	tier6_log(LOG_INFO, "[peer=%02x] tunnel created (%s) (port=%u)", id,
	    tier6_address(&peer->cathedral.addr), ntohs(peer->port));
}

/*
 * Delete an existing tunnel for the given peer if the
 * peer is no longer alive.
 */
static void
peer_delete(struct tier6_peer *peer)
{
	u_int8_t		id;
	struct tier6_mac	*mac;

	PRECOND(peer != NULL);

	if ((t6->now - peer->alive) < PEER_ALIVE_TIMEOUT) {
		tier6_log(LOG_INFO,
		    "[peer=%02x] tunnel not removed, peer is alive", peer->id);
		return;
	}

	while ((mac = LIST_FIRST(&peer->macs)) != NULL) {
		LIST_REMOVE(mac, list);
		free(mac);
	}

	id = peer->id;

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
	size_t			len;
	ssize_t			ret;
	struct kyrka_packet	pkt;
	u_int8_t		*ptr;
	socklen_t		socklen;

	PRECOND(peer != NULL);

	for (;;) {
		if ((ptr = kyrka_packet_recvbuf(peer->ctx, &pkt, &len)) == NULL)
			fatal("failed to get peer receive buffer");

		socklen = sizeof(sender);

		if ((ret = recvfrom(peer->fd, ptr, len, MSG_DONTWAIT,
		    (struct sockaddr *)&sender, &socklen)) == -1) {
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

		pkt.length = ret;

		if (tier6_inet_match(&sender, &peer->cathedral.addr))
			pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;
		else
			pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

		if (kyrka_purgatory_input(peer->ctx, &pkt) == -1) {
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
		peer_cathedral_alive(peer);
		break;
	case KYRKA_EVENT_LOGMSG:
		tier6_log(LOG_INFO, "[peer=%02x] log: %s",
		    peer->id, evt->logmsg.log);
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		in.s_addr = evt->peer.ip;
		peer_cathedral_alive(peer);

		if (evt->peer.flags & KYRKA_INFO_FLAG_SAME_EXTERNAL_IPV4) {
			peer->local_discovery = 1;
			break;
		}

		if (peer->local_discovery) {
			if (kyrka_p2p_active(peer->ctx, 0) == -1)
				fatal("failed to set p2p status");
			peer->local_discovery = 0;
		}

		if (peer->addr.sin_addr.s_addr != evt->peer.ip ||
		    peer->addr.sin_port != evt->peer.port) {
			peer->addr.sin_port = evt->peer.port;
			peer->addr.sin_addr.s_addr = evt->peer.ip;

			if (peer->cathedral.addr.sin_addr.s_addr !=
			    peer->addr.sin_addr.s_addr &&
			    peer->cathedral.addr.sin_port !=
			    peer->addr.sin_port) {
				if (kyrka_p2p_active(peer->ctx, 1) == -1)
					fatal("failed to set p2p status");

				tier6_log(LOG_INFO,
				    "[peer=%02x] p2p discovery %s:%u",
				    peer->id, inet_ntoa(in),
				    htons(evt->peer.port));

				peer->hb_ticks = 15;
				peer->hb_frequency = 1000;
			} else {
				if (kyrka_p2p_active(peer->ctx, 0) == -1)
					fatal("failed to set p2p status");
			}
		}
		break;
	case KYRKA_EVENT_REMEMBRANCE_RECEIVED:
		peer_cathedral_alive(peer);
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
peer_heaven_input(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	const struct tier6_ether	*eth;
	struct tier6_peer		*peer;
	u_int16_t			proto;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	peer = udata;

	if (pkt->length < sizeof(*eth))
		return;

	eth = kyrka_packet_data(pkt);
	proto = ntohs(eth->proto);

	switch (proto) {
	case TIER6_ETHER_TYPE_ARP:
	case TIER6_ETHER_TYPE_VLAN:
	case TIER6_ETHER_TYPE_IPV4:
	case TIER6_ETHER_TYPE_IPV6:
		break;
	case TIER6_ETHER_TYPE_HEARTBEAT:
		peer_heartbeat_recv(peer, pkt);
		return;
	case TIER6_ETHER_TYPE_DISC_PROBE:
		peer_discovery_ack(peer);
		/* FALLTHROUGH */
	case TIER6_ETHER_TYPE_DISC_ACK:
		memcpy(&peer->addr, &sender, sizeof(sender));

		if (kyrka_p2p_active(peer->ctx, 1) == -1)
			fatal("failed to set p2p status");

		tier6_log(LOG_INFO, "[peer=%02x] p2p discovery %s:%u",
		    peer->id, inet_ntoa(sender.sin_addr),
		    ntohs(sender.sin_port));
		return;
	default:
		return;
	}

	peer_mac_register(peer, eth, 0);

	if (tier6_platform_tap_write(eth, pkt->length) == -1)
		tier6_log(LOG_NOTICE, "tap write failed: %s", errno_s);
}

/*
 * Callback from libkyrka when ciphertext is available. This ciphertext
 * is sent to the current known address for our peer.
 */
static void
peer_purgatory_input(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	size_t			len;
	u_int8_t		*data;
	struct tier6_peer	*peer;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	peer = udata;

	if ((data = kyrka_packet_sendbuf(peer->ctx, pkt, &len)) == NULL)
		fatal("failed to get peer send buffer");

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
peer_kyrka_send(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	size_t			len;
	struct sockaddr_in	sin;
	u_int16_t		port;
	struct tier6_peer	*peer;
	u_int8_t		*data;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	peer = udata;

	port = be16toh(peer->cathedral.addr.sin_port);
	if (magic == KYRKA_CATHEDRAL_NAT_MAGIC)
		port++;

	sin.sin_family = AF_INET;
	sin.sin_port = htobe16(port);
	sin.sin_addr.s_addr = peer->cathedral.addr.sin_addr.s_addr;

	if ((data = kyrka_packet_sendbuf(peer->ctx, pkt, &len)) == NULL)
		fatal("failed to get peer cathedral send buffer");

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
 * Send a heartbeat packet to our peer if its time to do so. This heartbeat
 * contains information about our local ip addresses so we can decide if
 * we somehow want to move traffic to a local connection if we detect
 * that we can talk to our peer that way.
 */
static void
peer_heartbeat_send(struct tier6_peer *peer)
{
	int			idx;
	size_t			len;
	struct kyrka_packet	pkt;
	struct tier6_hb		*hb;
	struct sockaddr_in	*sin, *mask;
	struct ifaddrs		*ifa, *ifap;

	PRECOND(peer != NULL);

	if (peer->hb_next > 0 && t6->now < peer->hb_next)
		return;

	peer->hb_next = t6->now + peer->hb_frequency;

	if (peer->hb_ticks > 0) {
		peer->hb_ticks--;
		if (peer->hb_ticks == 0)
			peer->hb_frequency = 5000;
	}

	if ((hb = kyrka_packet_databuf(peer->ctx, &pkt, &len)) == NULL)
		fatal("failed to get peer data buffer for heartbeat");

	VERIFY(sizeof(*hb) <= len);
	memset(hb, 0, sizeof(*hb));

	hb->eth.proto = htons(TIER6_ETHER_TYPE_HEARTBEAT);

	if (peer->local_discovery) {
		idx = 0;
		hb->port = peer->port;

		if (getifaddrs(&ifap) == -1)
			fatal("getifaddrs: %s", errno_s);

		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (idx >= TIER6_HB_IPV4_MAX)
				break;

			if (!strcmp(ifa->ifa_name, t6->tapname))
				continue;

			if (t6->bridge != NULL &&
			    !strcmp(ifa->ifa_name, t6->bridge))
				continue;

			if (ifa->ifa_addr == NULL)
				continue;

			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;

			if (ifa->ifa_flags & (IFF_POINTOPOINT | IFF_LOOPBACK))
				continue;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			mask = (struct sockaddr_in *)ifa->ifa_netmask;

			hb->ips[idx] = sin->sin_addr.s_addr;
			hb->masks[idx] = mask->sin_addr.s_addr;

			idx++;
		}

		freeifaddrs(ifap);
	}

	if (tier6_inet_match(&peer->addr, &peer->cathedral.addr))
		pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;
	else
		pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	pkt.length = sizeof(*hb);

	if (kyrka_heaven_input(peer->ctx, &pkt) == -1 &&
	    kyrka_last_error(peer->ctx) != KYRKA_ERROR_NO_TX_KEY) {
		tier6_log(LOG_NOTICE, "[peer=%02x] kyrka_heaven_input: %d",
		    peer->id, kyrka_last_error(peer->ctx));
	}
}

/*
 * We received a heartbeat from our peer, check if we can move to a local
 * connection if possible and update its alive freshness.
 */
static void
peer_heartbeat_recv(struct tier6_peer *peer, struct kyrka_packet *pkt)
{
	int			idx;
	struct tier6_hb		*hb;
	struct sockaddr_in	*sin;
	u_int16_t		proto;
	struct ifaddrs		*ifap, *ifa;
	u_int32_t		ip, mask, net;

	PRECOND(peer != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length != sizeof(*hb)) {
		tier6_log(LOG_NOTICE, "invalid heartbeat packet of size %zu",
		    pkt->length);
		return;
	}

	hb = kyrka_packet_data(pkt);
	proto = ntohs(hb->eth.proto);
	VERIFY(proto == TIER6_ETHER_TYPE_HEARTBEAT);

	peer->alive = t6->now;

	if (peer->local_discovery == 0)
		return;

	if (hb->port == 0 || hb->ips[0] == 0)
		return;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs: %s", errno_s);

	for (idx = 0; idx < TIER6_HB_IPV4_MAX; idx++) {
		if (hb->ips[idx] == 0)
			break;

		hb->ips[idx] = ntohl(hb->ips[idx]);
		hb->masks[idx] = ntohl(hb->masks[idx]);

		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (!strcmp(ifa->ifa_name, t6->tapname))
				continue;

			if (ifa->ifa_addr == NULL)
				continue;

			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;

			if (ifa->ifa_flags & (IFF_POINTOPOINT | IFF_LOOPBACK))
				continue;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			ip = ntohl(sin->sin_addr.s_addr);

			sin = (struct sockaddr_in *)ifa->ifa_netmask;
			mask = ntohl(sin->sin_addr.s_addr);

			net = ip & mask;
			if (net == (hb->ips[idx] & hb->masks[idx]))
				break;
		}

		if (ifa != NULL) {
			hb->ips[idx] = htonl(hb->ips[idx]);
			peer_discovery_probe(peer, hb->ips[idx], hb->port);
		}
	}

	freeifaddrs(ifap);
}

/*
 * Send a discovery probe to our potential peer. If it exists there it will
 * answer with a discovery ack at which point we change peer address.
 *
 * This is only used if the cathedral tells us we share the same external
 * ipv4 address as our peer.
 */
static void
peer_discovery_probe(struct tier6_peer *peer, u_int32_t ip, u_int16_t port)
{
	size_t				len;
	struct kyrka_packet		pkt;
	struct sockaddr_in		addr;
	struct tier6_discovery		*disc;

	PRECOND(peer != NULL);
	PRECOND(ip != 0);
	PRECOND(port != 0);

	if (peer->addr.sin_addr.s_addr == ip && peer->addr.sin_port == port)
		return;

	if ((disc = kyrka_packet_databuf(peer->ctx, &pkt, &len)) == NULL)
		fatal("failed to get peer data buffer for discovery probe");

	VERIFY(sizeof(*disc) <= len);
	memset(disc, 0, sizeof(*disc));

	disc->eth.proto = htons(TIER6_ETHER_TYPE_DISC_PROBE);

	pkt.length = sizeof(*disc);
	pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	/*
	 * Temporarily override the destination address that is used
	 * in the peer_purgatory_input() function for sending an
	 * encrypted packet.
	 */
	memcpy(&addr, &peer->addr, sizeof(peer->addr));

	peer->addr.sin_port = port;
	peer->addr.sin_addr.s_addr = ip;

	if (kyrka_heaven_input(peer->ctx, &pkt) == -1 &&
	    kyrka_last_error(peer->ctx) != KYRKA_ERROR_NO_TX_KEY) {
		tier6_log(LOG_NOTICE, "[peer=%02x] kyrka_heaven_input: %d",
		    peer->id, kyrka_last_error(peer->ctx));
	}

	/* Restore current peer address. */
	memcpy(&peer->addr, &addr, sizeof(addr));
}

/*
 * Send a discovery ack back to our last sender address to let it know
 * we are alive and we have successfully received its probe.
 */
static void
peer_discovery_ack(struct tier6_peer *peer)
{
	size_t				len;
	struct kyrka_packet		pkt;
	struct sockaddr_in		addr;
	struct tier6_discovery		*disc;

	PRECOND(peer != NULL);

	if ((disc = kyrka_packet_databuf(peer->ctx, &pkt, &len)) == NULL)
		fatal("failed to get peer data buffer for discovery ack");

	VERIFY(sizeof(*disc) <= len);
	memset(disc, 0, sizeof(*disc));

	disc->eth.proto = htons(TIER6_ETHER_TYPE_DISC_ACK);

	pkt.length = sizeof(*disc);
	pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	/*
	 * Temporarily override the destination address that is used
	 * in the peer_purgatory_input() function for sending an
	 * encrypted packet.
	 */
	memcpy(&addr, &peer->addr, sizeof(peer->addr));
	memcpy(&peer->addr, &sender, sizeof(sender));

	if (kyrka_heaven_input(peer->ctx, &pkt) == -1 &&
	    kyrka_last_error(peer->ctx) != KYRKA_ERROR_NO_TX_KEY) {
		tier6_log(LOG_NOTICE, "[peer=%02x] kyrka_heaven_input: %d",
		    peer->id, kyrka_last_error(peer->ctx));
	}

	/* Restore current peer address. */
	memcpy(&peer->addr, &addr, sizeof(addr));
}

/*
 * Register the given MAC address as seen on the peer, these eventually
 * expire unless `fixed` is set to 1.
 */
static void
peer_mac_register(struct tier6_peer *peer,
    const struct tier6_ether *eth, int fixed)
{
	struct tier6_peer	*p0;
	struct tier6_mac	*mac;

	PRECOND(peer != NULL);
	PRECOND(eth != NULL);
	PRECOND(fixed == 0 || fixed == 1);

	mac = NULL;

	LIST_FOREACH(p0, &peers, list) {
		LIST_FOREACH(mac, &p0->macs, list) {
			if (!memcmp(mac->addr,
			    eth->src, TIER6_ETHERNET_MAC_LEN))
				break;
		}

		if (mac == NULL)
			continue;

		if (p0 != peer) {
			tier6_log(LOG_INFO,
			    "[mac] %02x:%02x:%02x:%02x:%02x:%02x moved %u->%u",
			    mac->addr[0], mac->addr[1], mac->addr[2],
			    mac->addr[3], mac->addr[4], mac->addr[5],
			    p0->id, peer->id);

			LIST_REMOVE(mac, list);
			LIST_INSERT_HEAD(&peer->macs, mac, list);
		}

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
	    "[peer=%02x] %02x:%02x:%02x:%02x:%02x:%02x discovered",
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

/*
 * Check if our cathedral is responsive or if we need to swap to another one.
 */
static void
peer_cathedral_check(struct tier6_peer *peer)
{
	int		was_cathedral;

	PRECOND(peer != NULL);
	PRECOND(t6->remembrance != NULL);

	if ((t6->now - peer->cathedral.last) > peer->cathedral.timeout) {
		tier6_log(LOG_NOTICE,
		    "[peer=%02x] cathedral timed out (%u)", peer->id,
		    peer->cathedral.timeout);

		if (peer->addr.sin_addr.s_addr ==
		    peer->cathedral.addr.sin_addr.s_addr)
			was_cathedral = 1;
		else
			was_cathedral = 0;

		if (tier6_remembrance_cathedral(&peer->cathedral) != -1) {
			tier6_log(LOG_NOTICE,
			    "[peer=%02x] switching to cathedral %s",
			    peer->id, tier6_address(&peer->cathedral.addr));

			if (was_cathedral) {
				memcpy(&peer->addr, &peer->cathedral.addr,
				    sizeof(peer->addr));
			}
		}
	}
}

/*
 * Mark our cathedral as alive and set the timeout to the non initial one.
 */
static void
peer_cathedral_alive(struct tier6_peer *peer)
{
	PRECOND(peer != NULL);

	peer->cathedral.last = t6->now;
	peer->cathedral.timeout = TIER6_CATHEDRAL_TIMEOUT;
}
