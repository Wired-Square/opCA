# The ACME broker

`opca-acme-broker` gives appliances that only speak ACME (Traefik, TrueNAS, Proxmox) certificates
from opCA without the root key leaving the desktop. It runs on a Debian host on your network,
holds a name-constrained subordinate CA that opCA signs, and answers ACME itself. The subordinate
can only issue for the domains opCA permitted it, and its key never leaves the host.

## Install

The broker needs Debian 12 (bookworm) or later with systemd, and nothing else: it no longer
needs step-ca.

```sh
sudo apt install ./opca-acme-broker_<version>_Linux_x64.deb
```

The broker's `.deb` is attached to each opCA release, for amd64. An arm64 `.deb` can be built
with `scripts/build-broker-deb.sh` (see [Building the `.deb`](#building-the-deb)). It installs `/usr/bin/opca-acme-broker`
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
| `host` | (required) | The name opCA dials, and the name the broker serves ACME as |
| `listen` | `[::]:9443` | The broker's API, for opCA |
| `domains` | none | The permitted domains to ask opCA for; left out, they're chosen in opCA |
| `acme_listen` | `[::]:443` | The ACME listener, for appliances |
| `state_dir` | `/var/lib/opca-acme` | Where the broker keeps its state |

**`host` must be a DNS name inside the permitted domains**, such as `acme.home.example` for
`home.example`, never an IP address. The ACME listener's TLS certificate is issued for `host` by
the subordinate, whose name constraints allow nothing else, so the broker refuses an enrolment
whose domains don't cover it. It warns on first start if `host` falls outside `domains`.

A `broker.toml` from an earlier version that still sets `step_ca` is refused at start, naming the
key. Delete the line.

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

## Enrol, renew and revoke in opCA

opCA manages its brokers from the **ACME Servers** page or the `opca broker` commands. Both
need the CA loaded, and every write takes the vault lock.

**Enrol.** On the ACME Servers page choose **Enrol Broker** and paste the pairing URI, or run:

```sh
opca broker enrol 'opca-enrol://acme.home.example:9443#pin=…&code=…'
```

opCA connects with the `pin` checked, before the code goes on the wire, and shows the broker's
host, address, key and versions, and the domains. If `broker.toml` sets `domains`, those are
used and can't be changed in opCA. Otherwise enter them in the dialog, or pass `--domain` once
per domain (`enrol` refuses without them). Confirm, or pass `--yes`, and opCA signs the
subordinate and hands it to the broker with the code. The terms are 30-day leaves, at most 45
days, over http-01, dns-01 and tls-alpn-01.

The first broker call in a vault creates a `CA_Operator` item holding the key opCA presents to
its brokers. Each session issues a short-lived certificate for that key, which isn't kept.

If the broker doesn't take the subordinate (the network drops, say), it shows as "signed, not
delivered". Enrol again with the same pairing string: opCA sends the same subordinate rather
than signing another.

**List and status.** The page, and `opca broker list`, show each broker's state, domains,
subordinate expiry and last contact, and flag one that needs attention:

- its subordinate expires within 30 days;
- opCA hasn't heard from it in over 35 days;
- it was signed but not delivered.

The dashboard's ACME Servers tile shows the same flags. **Status**, or `opca broker status <id>`,
asks the broker for its mode, subordinate and whether it is serving ACME (`issuing`, or
`acme down`), and how many certificates it has issued and revoked.

**Renew.** Renew one broker from its row menu or with `opca broker renew <id>`, or every broker
with **Renew All** or `opca broker renew --all`. Renewal is a deliberate action: do it at each
signing session, before the dashboard flags expiry. Each broker makes a fresh CSR over the same
key, opCA signs it, and the broker serves ACME with the new chain at once. The result is reported for
each broker; an unreachable one is never skipped silently, and `renew` exits non-zero unless
every broker renewed.

If `domains` in `broker.toml` has changed, nothing is signed and opCA asks you to confirm the new
domains: **Confirm and Renew** on the page, or `opca broker renew <id> --change-domains`. If the
new chain doesn't reach the broker, the next renewal signs afresh.

**Revoke.** **Revoke** in the row menu, or `opca broker revoke <id>`, puts the subordinate on the
CRL, regenerates the CRL and tells the broker, which stops serving ACME. The revocation stands even
if the broker can't be reached; revoke again to tell it once it's back.

**Issued certificates.** The page's **Issued** column counts the certificates each broker has
issued and revoked; click it to list them, with their names, expiry and state. opCA brings the
list up to date whenever it talks to the broker (status, enrolment, renewal, revoke), and keeps it
in the CA database. A broker that can't send it doesn't stop the call: opCA logs it and carries on.

**No external account binding yet.** ACME clients can't be required to use EAB. Any client that
can reach the ACME port can register, and still gets only names inside the permitted domains whose
challenges it passes. Limit who can reach port 443 at the network.

**What ACME clients get.** Accounts, orders over http-01, dns-01 and tls-alpn-01 (whichever opCA
set at pairing), account key changes and deactivation, and revocation by the ordering account or
by the certificate's own key. A wildcard is validated only by dns-01, IP addresses are refused, and
names outside the permitted domains are refused when the order is placed. An order lasts 24
hours. A certificate revoked through ACME shows as revoked in opCA after its next sync.

## Status

```sh
sudo opca-acme status
```

It reads the state directory, not the network, and prints the mode (`enrolling`, `enrolled` or
`revoked`), the pairing code's state, the subordinate's serial, expiry and permitted domains
once enrolled, and whether the broker is running.

`opca-acme` runs as root or as `opca-acme`. From root it switches to `opca-acme` before
touching the state, so nothing it writes locks the daemon out. Every command takes
`--config <path>`.

## Re-opening enrolment

To pair the host with another opCA, or after the root CA is replaced:

```sh
sudo opca-acme enrol --reopen
```

Only root can do this. It asks you to type `reopen` (or pass `--yes`), then:

- moves the enrolment and the CSR to `/var/lib/opca-acme/archive/<time>/`;
- deletes the subordinate key;
- makes a new key, a new CSR and a new pairing code, and prints the URI.

The running broker reloads, stops serving ACME and waits to pair again. Its API key, and so the
`pin`, stays the same. Revoke the old subordinate in opCA (**Revoke** on the ACME Servers page,
or `opca broker revoke <id>`). The broker is no longer enrolled, so opCA reports that it wasn't
told, which is expected here.

## Revoke

When opCA revokes the subordinate and tells the broker, the broker stops serving ACME and stays
revoked across restarts. It then answers opCA's status, revoke and issued-list calls and nothing
else. To use the host again, re-open enrolment.

Revoking with `opca subordinate revoke <id>`, or from the certificate list, puts the subordinate
on the CRL but doesn't reach the broker. Revoke from the ACME Servers page or with
`opca broker revoke <id>` to do both.

## Ports and the ACME directory

| Port | Direction | For |
|---|---|---|
| 9443 | opCA to broker | The broker's API. After pairing it admits only opCA's operator certificate |
| 443 | appliances to broker | ACME |
| 80 / 443 | broker to appliances | Checking http-01 and tls-alpn-01 challenges |
| 53 | broker to its resolvers | Checking dns-01 challenges, through the system's resolvers |

Point each appliance at the ACME directory:

```text
https://acme.home.example/acme/directory
```

Use `host`, plus `:<port>` if you changed `acme_listen`. Appliances must trust opCA's root
certificate: the listener's own certificate is issued for `host` by the subordinate, for 30 days
at most and never past the subordinate's end. The broker issues it on each new chain and at
start, and again two-thirds of the way through its life. Only names inside the permitted domains are issued, with the challenges and
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
| `acme.crt`, `acme.key` | The ACME listener's certificate and key, issued by the subordinate |
| `acme.db` (with `-wal`, `-shm`) | The ACME server's database: accounts, orders and issued certificates |
| `archive/` | What each re-opening set aside |
| `broker.pid`, `*.lock` | Runtime files |

**Never copy `subordinate.key`**, and don't back it up. A copy can issue for your domains until
the subordinate expires or is revoked. If the host is lost, install afresh, pair again and
revoke the old subordinate in opCA.

Worth backing up, for the record of what was issued: `acme.db` (with the broker stopped) and
`archive/`. A re-opening keeps `acme.db`: its accounts and issued certificates belong to the host,
not to one enrolment.

## Logs

```sh
journalctl -u opca-acme-broker
```

`systemctl reload opca-acme-broker` has the broker re-read its state.

## Upgrading

Install the new `.deb` over the old one. A running broker is restarted. Your `broker.toml` is
kept, and the state directory is untouched. Coming from a broker that ran step-ca, remove
`step_ca` from `broker.toml` if you set it, and then the `step-ca` package if nothing else uses
it. The old `step-ca*` files in the state directory are no longer read.

## As an ApplianceOS app

The broker also ships as the `opca-acme` app for ApplianceOS, one image per architecture (arm64
for now). It holds only the broker; there's no `opca-acme` command line in it. Its manifest
declares:

| | |
|---|---|
| Listeners | `api` on 9443 (opCA) and `acme` on 8443 (appliances), both on at install |
| Volume | `data`, at `/data`: the state lives in `/data/state` |
| Options | `host` (required) and `domains` (optional), as in `broker.toml` |

Only the console reaches its page, health and hooks: the app's sockets hang up on any other uid.

**Set `host` after installing.** Until it's set the app is healthy but does nothing else: it
reports that it needs a host, answers both ports with a 503 saying so, and makes no keys. Setting
the option restarts the app, which then starts as the broker does on Debian and logs the pairing
URI. On ApplianceOS after 0.1.10 the URI names the API's host port as the console mapped it,
which may not be 9443. An
appliance's ACME directory is `https://<host>:<acme port>/acme/directory`, with the `acme`
listener's host port.

Options come first; `/data/broker.toml`, with the same `host` and `domains` keys, second. A
blank option gives way to it.

**Open it from Apps** to see its page, as any role: the broker's state, host, domains and
subordinate, then the certificates it has issued, newest first, each with its names, serial,
validity and status: valid, expiring (in the last third of its lifetime, when ACME clients
renew), expired, or revoked with the reason. A filter shows only the revoked or the rest. The
page is read-only; revoke in opCA.

The app takes its own backups while it runs, so the box's backup holds `acme.db` (accounts and
issued certificates), the enrolment, its chain and its config, and **never the subordinate key**.
A restore is all or nothing, and the box keeps the key it holds. On the same box the broker
carries on as it was. On a fresh box, whose key is a new one, the issued certificates come back
but the enrolment doesn't: the broker wants enrolling again, and the restore says so and names
the old subordinate's serial, which you then revoke in opCA. A restore is refused onto a broker
enrolled with another key, onto a revoked broker by a backup from before the revocation, and onto
an app that still needs its `host`. Unsetting `host` doesn't stop the backups: they keep what the
broker left.

To build it and pack it into an archive the console's **Apps › Install** takes:

```sh
scripts/build-acme-app.sh [--keys <dir>] --platform linux/arm64
```

It needs Docker with buildx, OpenSSL 3, `jq`, npm, `wslib-appliance-xtask` for arm64, and an ApplianceOS checkout (`APPLIANCEOS`, by
default `../ApplianceOS`). It signs as source `opca-test` (`--source` changes it) with the
throwaway keys in `<dir>`, made there if it holds none, or without `--keys`, with
`OPCA_TEST_SIGNING_CERT` and `OPCA_TEST_SIGNING_KEY` from `.env` (base64 of `leaf.pem` and
`leaf.key`). Keep signing with the same leaf: a box's source verifies only the root it was given,
so new keys mean removing and reinstalling the app. Add the keys' `root.pem` under **Apps ›
Sources** with that name before installing. The page is built first, with npm from the Wired
Square mirror (`ui/.npmrc`). The image and the archive land in `target/acme-app/`. To run
the image locally as the console would:

```sh
OPCA_ACME_APP_IMAGE=$PWD/target/acme-app/opca-acme-<version>-arm64.tar \
    cargo test -p opca-acme-broker --test broker_docker the_app_image
```

## Building the `.deb`

```sh
scripts/build-broker-deb.sh --platform linux/amd64   # or linux/arm64, the default
```

It builds in a `rust:1.99-bookworm` container of that platform, through Docker's emulation when
it isn't the host's, and leaves the `.deb` in `target/acme-docker/<arch>/deb/`. An arm64 build
links with lld for the Cortex-A53 erratum 843419 fix and checks its binaries with
`wslib-appliance-xtask erratum-843419`, which must be on the `PATH`.
`crates/opca-acme-broker/tests/docker.sh` takes the same `--platform`, builds, then installs and
enrols the `.deb` under systemd in `debian:bookworm` of that platform. On a Docker network of its
own, with a Knot DNS server authoritative for the test domain, it then has real clients issue from
the broker: lego over http-01 and tls-alpn-01 (with a renewal, a revocation through ACME and an
out-of-domain refusal), certbot over http-01, and acme.sh over dns-01 for a wildcard and again
across a restart of the broker mid-order. Every image is pinned by tag.
