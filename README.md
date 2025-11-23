# tier6

Build a global ethernet network using sanctum p2p e2ee tunnels.

Tier6 uses a sanctum cathedral infrastructure to autodiscover peers
in its same network and establish p2p e2ee tunnels to each peer
in full mesh mode. All incoming traffic is dumped into a single
tap interface. Return traffic is only sent to peers on which
the destination MAC address has been seen as a source earlier,
acting like a soft-switch.

This is work in progress, no daemonization yet, no proper logging,
code is undocumented at the moment.

You don't want this yet.

## Configuration

You need a cathedral setup to run this, once you have the relevant
files you can create a simple configuration:

```
kek-id 01
cs-id 0f056e10
flock deadbeef00

tapname 0f056e10
cathedral 1.2.3.4:4500

kek-path deadbeef00/kek-0x01
cs-path deadbeef00/id-0f056e10
cosk-path deadbeef00/cosk-0f056e10
```

## Running

```
# tier6 t6.conf
```
