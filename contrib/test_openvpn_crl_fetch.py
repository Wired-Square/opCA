#!/usr/bin/env python3
"""
#
# test_openvpn_crl_fetch.py - Offline tests for openvpn-crl-fetch.sh
#
# Run with `python -m pytest contrib/test_openvpn_crl_fetch.py`. Needs OpenSSL (not
# LibreSSL) first on PATH. CRLs are generated in-test and served from file:// URLs or
# a local HTTP server on 127.0.0.1.
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

SCRIPT = Path(__file__).with_name('openvpn-crl-fetch.sh')
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def make_ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_crl(key, cert, next_update_in=timedelta(days=10), number=1, signer=None):
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(NOW - timedelta(days=1))
        .next_update(NOW + next_update_in)
        .add_extension(x509.CRLNumber(number), critical=False)
        .sign(signer or key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


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
    key, cert = make_ca('Test VPN CA')
    ca_path = tmp_path / 'ca.crt'
    ca_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, ca_path


@pytest.fixture
def installed(tmp_path, ca):
    """An existing crl-verify file, which failures must leave untouched."""
    key, cert, _ = ca
    path = tmp_path / 'openvpn' / 'crl.pem'
    path.parent.mkdir()
    path.write_bytes(make_crl(key, cert, number=1))
    return path


def fetch(url, ca_path, crl_path, **env):
    return subprocess.run(
        [str(SCRIPT), url, str(ca_path), str(crl_path)],
        env={**os.environ, **env}, capture_output=True, text=True, timeout=60,
    )


def publish(tmp_path, pem):
    path = tmp_path / 'published.pem'
    path.write_bytes(pem)
    return path.as_uri()


def test_installs_a_valid_crl(tmp_path, ca, installed):
    key, cert, ca_path = ca
    pem = make_crl(key, cert, number=2)

    result = fetch(publish(tmp_path, pem), ca_path, installed)

    assert result.returncode == 0, result.stderr
    assert installed.read_bytes() == pem
    assert installed.stat().st_mode & 0o777 == 0o644
    assert list(installed.parent.iterdir()) == [installed]


def test_first_install_needs_no_existing_file(tmp_path, ca):
    key, cert, ca_path = ca
    target = tmp_path / 'crl.pem'

    result = fetch(publish(tmp_path, make_crl(key, cert)), ca_path, target)

    assert result.returncode == 0, result.stderr
    assert target.exists()


def test_unchanged_crl_is_not_rewritten(tmp_path, ca, installed):
    _, _, ca_path = ca
    mtime = installed.stat().st_mtime_ns

    result = fetch(publish(tmp_path, installed.read_bytes()), ca_path, installed)

    assert result.returncode == 0, result.stderr
    assert 'Installed' not in result.stdout
    assert installed.stat().st_mtime_ns == mtime


def test_fetches_over_http(server, ca, installed):
    _, served, base = server
    key, cert, ca_path = ca
    pem = make_crl(key, cert, number=2)
    (served / 'crl.pem').write_bytes(pem)

    result = fetch(f'{base}/crl.pem', ca_path, installed)

    assert result.returncode == 0, result.stderr
    assert installed.read_bytes() == pem


def other_ca_crl(key, cert):
    other_key, other_cert = make_ca('Other CA')
    return make_crl(other_key, other_cert)


@pytest.mark.parametrize('make_pem, expected', [
    (lambda key, cert: make_crl(key, cert, signer=ec.generate_private_key(ec.SECP256R1())),
     'failed signature verification'),
    (other_ca_crl, "was issued by 'CN=Other CA', not the CA"),
    (lambda key, cert: make_crl(key, cert, next_update_in=-timedelta(hours=1)), 'expired at'),
    (lambda key, cert: b'<html>not a CRL</html>', 'is not a PEM CRL'),
])
def test_bad_crl_keeps_the_installed_one(tmp_path, ca, installed, make_pem, expected):
    key, cert, ca_path = ca
    before = installed.read_bytes()

    result = fetch(publish(tmp_path, make_pem(key, cert)), ca_path, installed)

    assert result.returncode == 1
    assert expected in result.stderr
    assert installed.read_bytes() == before
    assert list(installed.parent.iterdir()) == [installed]


def test_download_failure_alerts_slack_and_keeps_the_installed_one(server, ca, installed):
    httpd, _, base = server
    _, _, ca_path = ca
    before = installed.read_bytes()

    result = fetch(f'{base}/missing.pem', ca_path, installed, SLACK_WEBHOOK_URL=f'{base}/hook')

    assert result.returncode == 1
    assert installed.read_bytes() == before
    [post] = httpd.posts
    assert 'downloading' in json.loads(post)['text']
    assert '404' in json.loads(post)['text']


def test_near_expiry_installs_but_warns(tmp_path, ca, installed):
    key, cert, ca_path = ca
    pem = make_crl(key, cert, next_update_in=timedelta(days=2), number=2)

    result = fetch(publish(tmp_path, pem), ca_path, installed)

    assert result.returncode == 1
    assert installed.read_bytes() == pem
    assert 'expires in 47 hours' in result.stderr


def test_warn_days_is_configurable(tmp_path, ca, installed):
    key, cert, ca_path = ca
    pem = make_crl(key, cert, next_update_in=timedelta(days=2), number=2)

    result = fetch(publish(tmp_path, pem), ca_path, installed, CRL_WARN_DAYS='1')

    assert result.returncode == 0, result.stderr
