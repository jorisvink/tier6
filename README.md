# tier6

Build a global ethernet network using sanctum its p2p e2ee
tunnel infrastructure.

This is work in progress, no daemonization yet, no proper logging yet.

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
# tier6 my.conf
```
