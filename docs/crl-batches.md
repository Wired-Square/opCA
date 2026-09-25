# Pre-signed CRL batches

With batches on, opCA signs five CRLs ahead of time instead of one long-lived CRL. CRL *i*
has `thisUpdate` = T0 + *i*·7 days and `nextUpdate` 10 days after that. The batch is one PEM
file, `pending-crl/crl-batch.pem`, in the CA's private store. The notification Lambda copies
the CRL that is due to the public store, so the published CRL is renewed weekly without the
CA key leaving 1Password. Revoking a certificate re-signs and re-uploads the whole batch.

**An expired CRL rejects every OpenVPN client.** OpenVPN's `crl-verify` refuses all
connections once the CRL's `nextUpdate` has passed. A batch CRL lasts 10 days, so once the
batch runs out nothing renews it: re-sign it from opCA before that happens. The Lambda warns
once fewer than two CRLs are left to release, 10 to 17 days before the last one expires.

## Enabling batches

Turn batches on only once all of these are in place, in this order:

1. **Deploy the updated Lambda** (`notification/aws_lambda.py`). An older Lambda ignores the
   batch, and the published CRL lapses 10 days after the last manual upload.
2. **Set `PENDING_CRL_KEY`** on the Lambda to the batch's key in the private bucket: the
   private store's prefix followed by `pending-crl/crl-batch.pem`. It defaults to
   `pending-crl/crl-batch.pem`, which is right only when the private store is the bucket root.
   For a private store of `s3://ca-private-bucket/ca-database`, set
   `ca-database/pending-crl/crl-batch.pem`.
3. **Grant the Lambda's role the policy below.** Releasing needs `PutObject` on the public CRL.
4. **Turn batches on** in the CA settings in opCA, then generate the CRL.

Each run the Lambda verifies every CRL in the batch against `ca.crt`. It publishes the latest
one whose `thisUpdate` has passed, but only if its CRL number is higher than the published
CRL's, so it never rolls back. A batch with any unreadable, unnumbered or wrongly signed CRL
is refused as a whole and reported. The existing CRL checks then run on the published CRL.
While a batch is present, "CRL will expire soon" fires at 3 days (or `CRL_DAYS`, if lower),
which a weekly release never reaches. The Lambda reads the batch setting from the CA database
dump: with batches off it ignores any batch object, so a batch left behind is never released.
With batches on and no readable batch, it alerts and runs the usual CRL checks.

`notification/aws_lambda_test.py` runs the same handler with your own credentials, so it
releases a due CRL to the public bucket too.

### Lambda IAM policy

Least privilege; replace the bucket names and keys with the Lambda's environment values.
No `s3:ListBucket` is granted, so a missing batch reads as `AccessDenied`; either way the
Lambda reports the batch as missing or unreadable. If the private bucket uses SSE-KMS, the
role also needs `kms:Decrypt` on its key.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadCaDatabaseAndCrlBatch",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::ca-private-bucket/ca-database/ca.sqlite",
        "arn:aws:s3:::ca-private-bucket/ca-database/pending-crl/*"
      ]
    },
    {
      "Sid": "ReadCaCertificate",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ca-public-bucket/ca/ca.crt"
    },
    {
      "Sid": "ReleaseCrl",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::ca-public-bucket/ca/crl.pem"
    }
  ]
}
```

## VPN server CRL fetch

OpenVPN reads `crl-verify` from a local file, so each VPN server must fetch the published CRL
itself. [`contrib/openvpn-crl-fetch.sh`](../contrib/openvpn-crl-fetch.sh) does this safely:

```sh
openvpn-crl-fetch.sh CRL_URL CA_CERT CRL_PATH
```

It downloads the CRL to a temporary file beside `CRL_PATH`, checks that it was issued and
signed by `CA_CERT` and that its `nextUpdate` is in the future, then moves it into place
atomically. On any failure the installed CRL is kept. OpenVPN picks up the new file on the
next connection; no reload is needed. It needs bash, curl and OpenSSL 1.1.1 or later (not LibreSSL).

It exits non-zero, and posts to `SLACK_WEBHOOK_URL` if set, when the fetch fails or when the
installed CRL expires within `CRL_WARN_DAYS` days (default 3). A fetch that keeps failing
leaves an ageing CRL in place, and the Lambda cannot see VPN servers, so this is the alert
that catches it. Run it daily or more often, as root, so a missed release shows up days
before the CRL expires.

systemd, `/etc/systemd/system/openvpn-crl-fetch.service`:

```ini
[Unit]
Description=Fetch the opCA CRL for OpenVPN
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
ExecStart=/usr/local/sbin/openvpn-crl-fetch.sh https://ca.example.com/ca/crl.pem /etc/openvpn/server/ca.crt /etc/openvpn/server/crl.pem
```

`/etc/systemd/system/openvpn-crl-fetch.timer`:

```ini
[Unit]
Description=Fetch the opCA CRL for OpenVPN every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:17:00
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with `systemctl enable --now openvpn-crl-fetch.timer`. A failed run shows in
`systemctl --failed` and the journal.

cron, where a non-zero exit mails the output to `MAILTO`:

```cron
MAILTO=ops@example.com
17 */6 * * * root /usr/local/sbin/openvpn-crl-fetch.sh https://ca.example.com/ca/crl.pem /etc/openvpn/server/ca.crt /etc/openvpn/server/crl.pem
```

Cron mails any output, including the "Installed a new CRL" line on success. Append
`>/dev/null` to mail only on failure; errors go to stderr.
