# Setup tier6 using reliquary

This guide is a TLDR for how to use <a href="https://reliquary.se">Reliquary</a>
to setup a tier6 network from scratch with multiple nodes.

Pay close attention to the output of each reliquary-* command as it
gives you plenty of information.

## Admin computer

On the computer from which you will administrate reliquary we do the following:

* Create a new account
* Create a new flock under the account
* Generate wrapped keys for that flock
* Upload the wrapped keys to reliquary

This boils down to:

```
$ mkdir t6
$ cd t6
$ curl -O https://reliquary.se/reliquary-cli.tar
$ tar fvx reliquary-cli.tar
$ ./reliquary-register https://vessel.reliquary.se/v1
Your new account-key is:
    abcdef...
$ ./reliquary-flock-create
a36a6bce22675900
$ ambry generate a36a6bce22675900
$ ambry bundle a36a6bce22675900 a36a6bce22675900 60 keys
$ ./reliquary-ambry-upload a36a6bce22675900 keys
ambry uploaded
$
```

## Tier6 node

Joining a node into a flock is easy.

After joining a node into a flock you will need to approve it
via the admin computer you used earlier to setup reliquary.

Once the node is approved you need to distribute the correct KEK to the node.

Repeat the steps below on each node.

### On the node

```
$ mkdir t6
$ cd t6
$ curl -O https://reliquary.se/reliquary-cli.tar
$ tar fvx reliquary-cli.tar
$ ./reliquary-init https://vessel.reliquary.se/v1
$ ./reliquary-flock-join a36a6bce22675900
This device has been joined into a36a6bce22675900 and is pending approval by
the flock administrator.

    Device: c6e64bd8
$
```

### On the admin computer

```
$ ./reliquary-device-approve a36a6bce22675900 c6e64bd8
c6e64bd8 approved, please supply it with a36a6bce22675900/kek-data/kek-0x01
$
```

### KEK provision

Copy the indicated KEK from the admin computer in the **t6** directory to
the node using whatever secure method you prefer.

Once the KEK is on the node, install it on the node:

```
$ ./reliquary-kek-install a36a6bce22675900 01 /path/to/kek-0x01
The KEK is now installed as kek-0x01 in a36a6bce22675900.
$
```

### Tier6 configuration

Create **/etc/tier6.conf** on the node and include the following:

```
runas <user>

kek-id <kek-id>
cs-id <cs-id>
flock a36a6bce22675900

tapname mynet
cathedral <initial-cathedral>
```

To figure out the kek-id, cs-id you can run **reliquary-status** on
the node to obtain that information:

```
$ ./reliquary-status
Reliquary is initiated.
    flock a36a6bce22675900
        kek          01 (ready)
        device-id    c6e64bd8
```

To figure out an initial cathedral, select one at random from
the **reliquary-cathedral-list** command.

### Running tier6

Now we can start tier6 on each node:

```
# tier6 -d
```

Do not use -d if you wish to run it in foreground mode.
