# The ACME broker

`opca-acme-broker` gives appliances that only speak ACME (Traefik, TrueNAS, Proxmox) certificates
from opCA without the root key leaving the desktop. It runs on a Debian host on your network,
holds a name-constrained subordinate CA that opCA signs, and runs
[step-ca](https://smallstep.com/docs/step-ca/) as its child to answer ACME. The subordinate can
only issue for the domains opCA permitted it, and its key never leaves the host.

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
asks the broker for its mode, subordinate and whether step-ca is issuing.

**Renew.** Renew one broker from its row menu or with `opca broker renew <id>`, or every broker
with **Renew All** or `opca broker renew --all`. Renewal is a deliberate action: do it at each
signing session, before the dashboard flags expiry. Each broker makes a fresh CSR over the same
key, opCA signs it, and the broker reloads step-ca with the new chain. The result is reported for
each broker; an unreachable one is never skipped silently, and `renew` exits non-zero unless
every broker renewed.

If `domains` in `broker.toml` has changed, nothing is signed and opCA asks you to confirm the new
domains: **Confirm and Renew** on the page, or `opca broker renew <id> --change-domains`. If the
new chain doesn't reach the broker, the next renewal signs afresh.

**Revoke.** **Revoke** in the row menu, or `opca broker revoke <id>`, puts the subordinate on the
CRL, regenerates the CRL and tells the broker, which stops step-ca. The revocation stands even
if the broker can't be reached; revoke again to tell it once it's back.

**No external account binding.** ACME clients can't be required to use EAB: open-source step-ca
0.28.1 refuses to create EAB keys ("only available in Certificate Manager"). Any client that can
reach the ACME port can register, and still gets only names inside the permitted domains whose
challenges it passes. Limit who can reach port 443 at the network.

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
`pin`, stays the same. Revoke the old subordinate in opCA (**Revoke** on the ACME Servers page,
or `opca broker revoke <id>`). The broker is no longer enrolled, so opCA reports that it wasn't
told, which is expected here.

## Revoke

When opCA revokes the subordinate and tells the broker, the broker stops step-ca and stays
revoked across restarts. It then answers opCA's status and revoke calls and nothing else. To use
the host again, re-open enrolment.

Revoking with `opca subordinate revoke <id>`, or from the certificate list, puts the subordinate
on the CRL but doesn't reach the broker. Revoke from the ACME Servers page or with
`opca broker revoke <id>` to do both.

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
