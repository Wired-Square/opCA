# Certificate delivery

A server that makes its own key sends opCA only a CSR. opCA signs it and publishes the
certificate to the public store, and [`contrib/cert-fetch.sh`](../contrib/cert-fetch.sh) on the
server fetches it under a timer, checks it, installs it and reloads the service. Renewing a
published certificate keeps the key and publishes the renewal, so a renewal reaches the server
with nothing done there.

Publishing is per certificate, by choice: a public store listing every VPN client's name would
be an inventory, so publish only the certificates of servers that fetch them.

## Where a certificate is published

A certificate is published as `certs/<CN>.pem` in the public store, beside `ca.crt` and
`crl.pem`. Characters in the CN outside `A-Z`, `a-z`, `0-9`, `.` and `-` become `_`:

| CN | Object |
|---|---|
| `www.example.com` | `certs/www.example.com.pem` |
| `*.example.com` | `certs/_.example.com.pem` |

The object is the leaf certificate's PEM only; the server already has `ca.crt`. A CN names one
object, so publishing a certificate unpublishes the others with its CN, and the latest publish
wins. Revoked, expired, CA and subordinate CA certificates are refused, as is one with no CN.

An `rsync://` public store needs the `certs/` directory to exist before the first publish.
`s3://` and `sftp://` stores need nothing.

## Setting up a server

1. **Make the key and CSR on the server.** The key never leaves it:

   ```sh
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout /etc/ssl/private/www.example.com.key \
     -out www.example.com.csr -subj "/CN=www.example.com"
   chmod 600 /etc/ssl/private/www.example.com.key
   ```

   On macOS's LibreSSL add `-pkeyopt ec_param_enc:named_curve`, or opCA refuses the CSR.

2. **Sign it in opCA**, on the CSR page's Sign tab or with
   `opca -v <vault> csr sign -c www.example.com.csr -t webserver`.

3. **Publish it**, with Publish in the certificate's actions menu or
   `opca -v <vault> cert publish www.example.com`. The certificate page then shows it as
   published, and when. `opca ca list` has a Published column.

4. **Install the script and the CA certificate on the server**: `cert-fetch.sh` to
   `/usr/local/sbin/`, and `ca.crt` to a local path, fetched once and checked by hand. The
   script checks everything else against it.

5. **Run the script once by hand**, then under a timer (below). It needs bash, curl and OpenSSL
   1.1.1 or later (not LibreSSL):

   ```sh
   cert-fetch.sh CERT_URL CA_CERT CRL_URL KEY_PATH CERT_PATH [RELOAD_COMMAND]
   ```

   It downloads the certificate and the CRL, and installs the certificate at `CERT_PATH` only if
   it chains to `CA_CERT`, is not on the CRL (whose signature it checks), has not expired,
   matches the key at `KEY_PATH` and expires later than the installed one. It then runs
   `RELOAD_COMMAND`, such as `systemctl reload nginx`, under `sh`. An unchanged certificate is
   left alone and nothing is reloaded. On any failure the installed file is kept, and the script
   exits non-zero and posts to `SLACK_WEBHOOK_URL` if set.

   `CERT_PATH` holds the leaf only. That serves clients that trust the opCA root, which every
   client of a private CA must.

### systemd

`/etc/systemd/system/cert-fetch.service`:

```ini
[Unit]
Description=Fetch this server's opCA certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
ExecStart=/usr/local/sbin/cert-fetch.sh https://ca.example.com/ca/certs/www.example.com.pem /etc/ssl/opca/ca.crt https://ca.example.com/ca/crl.pem /etc/ssl/private/www.example.com.key /etc/ssl/certs/www.example.com.pem "systemctl reload nginx"
```

`/etc/systemd/system/cert-fetch.timer`:

```ini
[Unit]
Description=Fetch this server's opCA certificate daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with `systemctl enable --now cert-fetch.timer`. A failed run shows in
`systemctl --failed` and the journal.

### cron

A non-zero exit mails the output to `MAILTO`:

```cron
MAILTO=ops@example.com
43 3 * * * root /usr/local/sbin/cert-fetch.sh https://ca.example.com/ca/certs/www.example.com.pem /etc/ssl/opca/ca.crt https://ca.example.com/ca/crl.pem /etc/ssl/private/www.example.com.key /etc/ssl/certs/www.example.com.pem "systemctl reload nginx" >/dev/null
```

The `>/dev/null` drops the "Installed a new certificate" line, so only failures are mailed.

## Renewing

Renewing a published certificate, in the app, in bulk or with `opca cert renew`, signs the
renewal from the stored CSR and publishes it under the same CN. The server's next run installs
it with no change to its key.

If that upload fails, the renewal still stands and is stored. The app's new certificate page
says why publishing failed, `opca cert renew` prints it, and bulk renew logs it in the Activity
Log. Publish the renewal again to retry: until then the server keeps the old certificate.

A rekey makes a new key in opCA, which won't match the server's, so a rekeyed certificate is
not republished. To change a server's key, make a new key and CSR on the server and start
again from step 2.

## Revoking

Revoking a certificate doesn't remove its published object: the CRL is the revocation channel.
Upload the regenerated CRL to the public store (the CRL page, or `opca crl upload`) unless
batches release it. The script then refuses the revoked certificate and alerts, keeping what
is installed, so issue and publish a replacement.

## Rebuilding the CA database

`opca database rebuild` rebuilds the database from 1Password items, which don't record what was
published. Every certificate comes back unpublished, so its renewals would not be published:
publish each server's certificate again after a rebuild.
