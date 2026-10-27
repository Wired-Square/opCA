#!/usr/bin/env python3
"""
#
# test_cert_fetch.py - Offline tests for cert-fetch.sh
#
# Run with `python -m pytest contrib/test_cert_fetch.py`. Needs OpenSSL (not LibreSSL)
# first on PATH. The CA, CRLs and certificates are generated in-test and served from
# file:// URLs or a local HTTP server on 127.0.0.1.
#
"""

import json
import os
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = Path(__file__).with_name('cert-fetch.sh')
NOW = datetime.now(timezone.utc).replace(microsecond=0)
PEM = serialization.Encoding.PEM


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(name(cn))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca, server_key, serial, expires_in=timedelta(days=90)):
    ca_key, ca_cert = ca
    return (
        x509.CertificateBuilder()
        .subject_name(name('www.example.com'))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOW + expires_in - timedelta(days=365))
        .not_valid_after(NOW + expires_in)
        .sign(ca_key, hashes.SHA256())
        .public_bytes(PEM)
    )


def make_crl(ca, revoked=(), next_update_in=timedelta(days=10), signer=None):
    key, cert = ca
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(NOW - timedelta(days=1))
        .next_update(NOW + next_update_in)
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(NOW - timedelta(hours=1))
            .build()
        )
    return builder.sign(signer or key, hashes.SHA256()).public_bytes(PEM)


class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        self.server.posts.append(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def server(tmp_path):
    served = tmp_path / 'served'
    served.mkdir()
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=served))
    httpd.posts = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, served, f'http://127.0.0.1:{httpd.server_address[1]}'
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def ca(tmp_path):
    ca = make_ca('Test CA')
    path = tmp_path / 'ca.crt'
    path.write_bytes(ca[1].public_bytes(PEM))
    return ca, path


@pytest.fixture
def server_key(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / 'server.key'
    path.write_bytes(key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key, path


@pytest.fixture
def installed(tmp_path, ca, server_key):
    """The certificate the server runs today, which failures must leave untouched."""
    path = tmp_path / 'tls' / 'server.crt'
    path.parent.mkdir()
    path.write_bytes(make_leaf(ca[0], server_key[0], serial=2, expires_in=timedelta(days=30)))
    return path


def serve(tmp_path, file_name, pem):
    path = tmp_path / file_name
    path.write_bytes(pem)
    return path.as_uri()


def fetch(tmp_path, ca, server_key, cert_path, cert_pem, crl_pem=None, reload=None, **env):
    ca, ca_path = ca
    args = [
        str(SCRIPT),
        serve(tmp_path, 'published.pem', cert_pem),
        str(ca_path),
        serve(tmp_path, 'crl.pem', crl_pem or make_crl(ca)),
        str(server_key[1]),
        str(cert_path),
    ]
    if reload is not None:
        args.append(reload)
    return subprocess.run(
        args, env={**os.environ, **env}, capture_output=True, text=True, timeout=60,
    )


def reload_marker(tmp_path):
    marker = tmp_path / 'reloaded'
    return marker, f'touch {marker}'


def test_installs_a_newer_cert_and_reloads(tmp_path, ca, server_key, installed):
    pem = make_leaf(ca[0], server_key[0], serial=3)
    marker, reload = reload_marker(tmp_path)

    result = fetch(tmp_path, ca, server_key, installed, pem, reload=reload)

    assert result.returncode == 0, result.stderr
    assert installed.read_bytes() == pem
    assert installed.stat().st_mode & 0o777 == 0o644
    assert list(installed.parent.iterdir()) == [installed]
    assert marker.exists()


def test_first_install_needs_no_existing_file(tmp_path, ca, server_key):
    target = tmp_path / 'server.crt'

    result = fetch(tmp_path, ca, server_key, target, make_leaf(ca[0], server_key[0], serial=3))

    assert result.returncode == 0, result.stderr
    assert target.exists()


def test_the_installed_cert_is_not_rewritten_or_reloaded(tmp_path, ca, server_key, installed):
    mtime = installed.stat().st_mtime_ns
    marker, reload = reload_marker(tmp_path)

    result = fetch(tmp_path, ca, server_key, installed, installed.read_bytes(), reload=reload)

    assert result.returncode == 0, result.stderr
    assert 'Installed' not in result.stdout
    assert installed.stat().st_mtime_ns == mtime
    assert not marker.exists()


def test_fetches_over_http(server, tmp_path, ca, server_key, installed):
    _, served, base = server
    pem = make_leaf(ca[0], server_key[0], serial=3)
    (served / 'www.example.com.pem').write_bytes(pem)
    (served / 'crl.pem').write_bytes(make_crl(ca[0]))

    result = subprocess.run(
        [str(SCRIPT), f'{base}/www.example.com.pem', str(ca[1]), f'{base}/crl.pem',
         str(server_key[1]), str(installed)],
        capture_output=True, text=True, timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert installed.read_bytes() == pem


def other_key(ca, _):
    return make_leaf(ca, ec.generate_private_key(ec.SECP256R1()), serial=3)


def other_ca(cn):
    return lambda _, key: make_leaf(make_ca(cn), key, serial=3)


@pytest.mark.parametrize('make_pem, crl_revokes, expected', [
    (other_key, (), 'does not match the private key'),
    (other_ca('Other CA'), (), 'failed verification against the CA'),
    (other_ca('Test CA'), (), 'failed verification against the CA'),
    (lambda ca, key: make_leaf(ca, key, serial=3, expires_in=-timedelta(days=1)), (),
     'certificate has expired'),
    (lambda ca, key: make_leaf(ca, key, serial=3, expires_in=timedelta(days=20)), (),
     'expires no later than the installed certificate'),
    (lambda ca, key: make_leaf(ca, key, serial=3), (3,), 'certificate revoked'),
    (lambda ca, key: b'<html>not a certificate</html>', (), 'is not a PEM certificate'),
])
def test_a_bad_cert_keeps_the_installed_one(
        tmp_path, ca, server_key, installed, make_pem, crl_revokes, expected):
    before = installed.read_bytes()
    marker, reload = reload_marker(tmp_path)

    result = fetch(tmp_path, ca, server_key, installed, make_pem(ca[0], server_key[0]),
                   crl_pem=make_crl(ca[0], revoked=crl_revokes), reload=reload)

    assert result.returncode == 1
    assert expected in result.stderr
    assert f'Kept {installed}' in result.stderr
    assert installed.read_bytes() == before
    assert list(installed.parent.iterdir()) == [installed]
    assert not marker.exists()


@pytest.mark.parametrize('make_crl_pem, expected', [
    (lambda ca: make_crl(ca, signer=ec.generate_private_key(ec.SECP256R1())),
     'failed signature verification'),
    (lambda ca: make_crl(make_ca('Other CA')), "was issued by 'CN=Other CA', not the CA"),
    (lambda ca: make_crl(ca, next_update_in=-timedelta(hours=1)), 'expired at'),
    (lambda ca: b'<html>not a CRL</html>', 'is not a PEM CRL'),
])
def test_a_bad_crl_keeps_the_installed_cert(
        tmp_path, ca, server_key, installed, make_crl_pem, expected):
    before = installed.read_bytes()

    result = fetch(tmp_path, ca, server_key, installed,
                   make_leaf(ca[0], server_key[0], serial=3), crl_pem=make_crl_pem(ca[0]))

    assert result.returncode == 1
    assert expected in result.stderr
    assert installed.read_bytes() == before


def test_download_failure_alerts_slack_and_keeps_the_installed_one(
        server, ca, server_key, installed):
    httpd, served, base = server
    (served / 'crl.pem').write_bytes(make_crl(ca[0]))
    before = installed.read_bytes()

    result = subprocess.run(
        [str(SCRIPT), f'{base}/missing.pem', str(ca[1]), f'{base}/crl.pem',
         str(server_key[1]), str(installed)],
        env={**os.environ, 'SLACK_WEBHOOK_URL': f'{base}/hook'},
        capture_output=True, text=True, timeout=60,
    )

    assert result.returncode == 1
    assert installed.read_bytes() == before
    [post] = httpd.posts
    text = json.loads(post)['text']
    assert 'downloading' in text and '404' in text


def test_a_failed_reload_installs_but_alerts(tmp_path, ca, server_key, installed):
    pem = make_leaf(ca[0], server_key[0], serial=3)

    result = fetch(tmp_path, ca, server_key, installed, pem, reload='echo nginx down >&2; false')

    assert result.returncode == 1
    assert installed.read_bytes() == pem
    assert "'echo nginx down >&2; false' failed: nginx down" in result.stderr


def test_wrong_arguments_print_the_usage():
    result = subprocess.run([str(SCRIPT), 'a', 'b'], capture_output=True, text=True, timeout=60)

    assert result.returncode == 2
    assert 'Usage:' in result.stderr
