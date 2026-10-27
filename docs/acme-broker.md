# The ACME broker

`opca-acme-broker` gives appliances that only speak ACME (Traefik, TrueNAS, Proxmox) certificates
from opCA without the root key leaving the desktop. It runs on a Debian host on your network,
holds a name-constrained subordinate CA that opCA signs, and runs
[step-ca](https://smallstep.com/docs/step-ca/) as its child to answer ACME. The subordinate can
only issue for the domains opCA permitted it, and its key never leaves the host.

**Pairing from the opCA app isn't available yet.** The broker side is complete, but opCA's
page for adding and renewing brokers comes in a later release. Until then a subordinate can be
signed by hand (`opca subordinate sign`), which doesn't use the broker.

## Install

The broker needs Debian 12 (bookworm) or later with systemd, and step-ca 0.28.1 or newer.
step-ca isn't in Debian's archive, so install smallstep's package first:

```sh
curl -fsSLO https://github.com/smallstep/certificates/releases/download/v0.28.1/step-ca_0.28.1-1_amd64.deb
sudo apt install ./step-ca_0.28.1-1_amd64.deb
sudo apt install ./opca-acme-broker_<version>_Linux_x64.deb
```

The broker's `.deb` is attached to each opCA release, for amd64 only so far. It installs `/usr/bin/opca-acme-broker`
(the daemon), `/usr/bin/opca-acme` (its command line), an `opca-acme` system user, the
`opca-acme-broker` systemd unit and `/etc/opca-acme/broker.toml`. The unit is neither enabled
nor started until you configure it.

## Configure

Edit `/etc/opca-acme/broker.toml`. Only `host` is required:

```toml
host = "acme.home.example"
domains = ["home.example"]
```

| Setting | Default | What it is |
|---|---|---|
| `host` | (required) | The name opCA dials, and the name step-ca serves ACME as |
| `listen` | `[::]:9443` | The broker's API, for opCA |
| `domains` | none | The permitted domains to ask opCA for; left out, they're chosen in opCA |
| `acme_listen` | `[::]:443` | step-ca's ACME listener, for appliances |
| `step_ca` | `/usr/bin/step-ca` | The step-ca the broker runs |
| `state_dir` | `/var/lib/opca-acme` | Where the broker keeps its state |

**`host` must be a DNS name inside the permitted domains**, such as `acme.home.example` for
`home.example`, never an IP address. step-ca's own TLS certificate is issued for `host` by the
subordinate, whose name constraints allow nothing else, so the broker refuses an enrolment
whose domains don't cover it. It warns on first start if `host` falls outside `domains`.

Then start it:

```sh
sudo systemctl enable --now opca-acme-broker
```

## Pair with opCA

On its first start the broker makes the subordinate key and its CSR, its own API certificate
and a one-time pairing code, and logs the pairing URI:

```text
opca-enrol://acme.home.example:9443#pin=<64 hex digits>&code=<code>
```

The `pin` is the hash of the broker's API key, which opCA checks before it sends the code. Five
wrong attempts spend the code. To print a URI later, issue a new code; the old one stops
working:

```sh
sudo opca-acme pairing
```

`pairing` works only while the broker is waiting to pair.

## Status

```sh
sudo opca-acme status
```

It reads the state directory, not the network, and prints the mode (`enrolling`, `enrolled` or
`revoked`), the pairing code's state, the subordinate's serial, expiry and permitted domains
once enrolled, and whether the broker and step-ca are running.

`opca-acme` runs as root or as `opca-acme`. From root it switches to `opca-acme` before
touching the state, so nothing it writes locks the daemon out. Every command takes
`--config <path>`.

## Re-opening enrolment

To pair the host with another opCA, or after the root CA is replaced:

```sh
sudo opca-acme enrol --reopen
```

Only root can do this. It asks you to type `reopen` (or pass `--yes`), then:

- moves the enrolment and step-ca's config and database to
  `/var/lib/opca-acme/archive/<time>/`;
- deletes the subordinate key;
- makes a new key, a new CSR and a new pairing code, and prints the URI.

The running broker reloads, stops step-ca and waits to pair again. Its API key, and so the
`pin`, stays the same. Revoke the old subordinate in opCA: `opca subordinate revoke <id>`,
with the id from `opca subordinate list`.

## Revoke

When opCA revokes the subordinate and tells the broker, the broker stops step-ca and stays
revoked across restarts. It then answers opCA's status and revoke calls and nothing else. To use
the host again, re-open enrolment.

Revoking with `opca subordinate revoke <id>` alone puts the subordinate on the CRL but doesn't reach
the broker.

## Ports and the ACME directory

| Port | Direction | For |
|---|---|---|
| 9443 | opCA to broker | The broker's API. After pairing it admits only opCA's operator certificate |
| 443 | appliances to broker | ACME |
| 80 / 443 | broker to appliances | step-ca checking http-01 and tls-alpn-01 challenges |

Point each appliance at the ACME directory:

```text
https://acme.home.example/acme/acme/directory
```

Use `host`, plus `:<port>` if you changed `acme_listen`. Appliances must trust opCA's root
certificate. Only names inside the permitted domains are issued, with the challenges and
lifetimes opCA set at pairing.

## The state directory

`/var/lib/opca-acme` is owned by `opca-acme` and readable by nobody else.

| Path | What it is |
|---|---|
| `subordinate.key` | The subordinate CA's private key, unencrypted |
| `subordinate.csr` | Its certificate request |
| `api.crt`, `api.key` | The broker's API certificate and key; the pairing pin is this key's |
| `pairing-code` | The pairing code's hash and attempts |
| `enrolment.json` | The signed chain, opCA's operator pin and the issuance settings |
| `step-ca.json`, `step-ca-root.crt`, `step-ca-intermediate.crt` | step-ca's config, written from the enrolment |
| `step-ca-db/` | step-ca's database: ACME accounts, orders and issued certificates |
| `archive/` | What each re-opening set aside |
| `broker.pid`, `step-ca.pid`, `*.lock` | Runtime files |

**Never copy `subordinate.key`**, and don't back it up. A copy can issue for your domains until
the subordinate expires or is revoked. If the host is lost, install afresh, pair again and
revoke the old subordinate in opCA.

Worth backing up, for the record of what was issued: `step-ca-db/` and `archive/`.

## Logs

```sh
journalctl -u opca-acme-broker
```

step-ca's output is in the same journal. `systemctl reload opca-acme-broker` has the broker
re-read its state.

## Upgrading

Install the new `.deb` over the old one. A running broker is restarted. Your `broker.toml` is
kept, and the state directory is untouched.
