# tier6

Build a global ethernet network using sanctum p2p e2ee tunnels.

Tier6 uses the <a href="https://github.com/jorisvink/sanctum">sanctum</a>
protocol and its cathedrals to autodiscover peers in the same flock and
establish p2p e2ee tunnels to each peer in full mesh mode. All incoming
traffic is dumped into a single tap interface. Return traffic is only
sent to peers on which the destination MAC address has been seen as
a source earlier, acting like a soft-switch.

```
   +--------+     p2p e2ee     +--------+
   | node 1 | <--------------> | node 2 |
   +--------+                  +--------+
         ^  ^                  ^  ^
         |  |____           ___|  |
         |      v           v     |
         |     +-------------+    |
         |     |   virtual   |    |
p2p e2ee |     |   ethernet  |    | p2p e2ee
         |     +-------------+    |
         |            ^           |
         |            |           |
         |       +--------+       |
         +-----> | node 3 | <-----+
                 +--------+
```

Tier6 is only L2, it does not autoconfigure your interfaces.
You are in charge of that.

## Tunnels

For details on how the underlying tunnels works see
<a href="https://github.com/jorisvink/sanctum/blob/master/docs/crypto.md">docs/crypto.md</a> in the sanctum repository.

## Building

Tier6 works on Linux, OpenBSD and MacOS.

You need <a href="https://github.com/jorisvink/libkyrka">libkyrka</a> and
pkg-config installed, plus whatever libs libkyrka needed (eg: libsodium).

```
$ make
```

**Note**: Use gmake on OpenBSD.

## Configuration

You need a cathedral setup to run this, once you have the relevant
files you can create a simple configuration. See the
[example configuration](example.conf) in this repository.

A community cathedral network can be found at
<a href="https://reliquary.se">The Reliquary</a>.

The configuration supports reliquary file paths out of the box.

## Running

```
# tier6 t6.conf
```
