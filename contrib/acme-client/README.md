# ACME client

A container that keeps a certificate from an RFC 8555 server, such as the opCA ACME broker, using
[lego](https://go-acme.github.io/lego/). It is configured only by environment variables, read from
`.env` by Compose. [.env.example](.env.example) documents every one.

The entrypoint, [acme-client.sh](acme-client.sh), orders a certificate when there is none under
`ACME_DATA`, then checks every `ACME_CHECK_INTERVAL` seconds and renews it once it is within
`ACME_RENEW_DAYS` of expiry. `ACME_HOOK` runs under `sh` after each issue or renewal. A failed
pass is tried again after `ACME_RETRY_INTERVAL` seconds. `ACME_ONCE=1` makes one pass and exits
with its status, for cron or a one-shot job.

## Quick start against an opCA broker

```sh
cd contrib/acme-client
cp .env.example .env                 # then set ACME_SERVER, ACME_EMAIL and ACME_DOMAINS
cp /path/to/root.pem ca.pem          # the CA's root, which the broker's TLS chains to
docker compose up -d --build
docker compose logs -f
```

`ACME_SERVER` is the broker's directory, `https://<host>:8443/acme/directory`. The broker needs
no external account binding and takes DNS names only. It issues 30-day leaves, which the default
renews with 10 days, a third of their life, left.

The certificate and its chain end up at `/data/certificates/<first domain>.crt`, with the key
beside it as `.key`, in the `data` volume.

## Trusting the root

lego trusts only the PEM file at `ACME_CA_BUNDLE` (it becomes `LEGO_CA_CERTIFICATES`). For an
opCA broker that is the CA's root certificate. Export it from opCA, save it as `ca.pem` beside
`compose.yaml`, and Compose mounts it at `/etc/acme/ca.pem`. A broker on a subordinate still
chains to the root, so the root alone is enough. For a public CA, set
`ACME_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`.

## Challenges

- **`http`**: lego answers http-01 on port 80, which Compose publishes. The server must reach
  each name on port 80. Another port is `ACME_ARGS=--http.port :8080`, and a web server that
  already holds port 80 can serve the token with `ACME_ARGS=--http.webroot /srv/www`.
- **`tls`**: tls-alpn-01 on port 443, also published. Use it when port 80 is closed.
- **`dns:<provider>`**: dns-01 through any of lego's DNS providers, e.g. `dns:cloudflare`. Set
  the provider's own variables in `.env`, e.g. `CLOUDFLARE_DNS_API_TOKEN`; they pass straight
  through. `docker run --rm goacme/lego dnshelp -c cloudflare` lists a provider's variables.
  It is the only challenge for a wildcard name, and needs no published port, so drop `ports`
  from `compose.yaml`.

Changing `ACME_DOMAINS` without changing its first name keeps renewing the old certificate.
Remove the files under `/data/certificates/` to order a new one.

## Baking it into another image

The entrypoint is POSIX `sh` and needs only `lego` on `PATH`, plus `cksum` and `sleep`. Copy both
in, and run it beside the app or in place of its own entrypoint:

```dockerfile
COPY --from=goacme/lego:v4.25.2 /lego /usr/local/bin/lego
COPY contrib/acme-client/acme-client.sh /usr/local/bin/acme-client.sh
```

Point `ACME_HOOK` at whatever makes the app pick up the new files, e.g.
`ACME_HOOK='nginx -s reload'`. `ACME_CERT` and `ACME_KEY` hold their paths while it runs. The
script stops promptly on `SIGTERM`, even while waiting between checks.

## Tests

`python -m pytest contrib/acme-client` runs the entrypoint against a fake lego. With
`OPCA_ACME_CLIENT_DOCKER_TEST=1` it also builds the image and orders a certificate from
[Pebble](https://github.com/letsencrypt/pebble) on an internal Docker network.
