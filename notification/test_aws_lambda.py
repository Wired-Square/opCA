#!/usr/bin/env python3
"""
#
# test_aws_lambda.py - Offline unit tests for the notification Lambda's checks
#
# Run with `python -m pytest notification/test_aws_lambda.py`. No AWS, S3 or
# Slack calls: keys, the CA certificate and the CRL are generated in-test.
#
"""

import os
import sqlite3
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def aws_lambda(monkeypatch):
    for var, value in (('DAYS', '30'), ('CRL_DAYS', '7')):
        monkeypatch.setenv(var, os.environ.get(var, value))

    import aws_lambda

    monkeypatch.setattr(aws_lambda, 'days', 30)
    monkeypatch.setattr(aws_lambda, 'crl_days', 7)
    # CRL times are whole seconds.
    monkeypatch.setattr(aws_lambda, 'now', aws_lambda.now.replace(microsecond=0))
    return aws_lambda


def make_key(kind):
    if kind == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key({'p256': ec.SECP256R1(), 'p384': ec.SECP384R1()}[kind])


def make_pem_ca_and_crl(kind, now, crl_expires_in=timedelta(days=30), crl_signer=None):
    key = make_key(kind)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'Test {kind} CA')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    next_update = now + crl_expires_in
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(next_update - timedelta(days=30))
        .next_update(next_update)
        .sign(crl_signer or key, hashes.SHA384() if kind == 'p384' else hashes.SHA256())
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        crl.public_bytes(serialization.Encoding.PEM).decode(),
    )


def run_checks(aws_lambda, tmp_path, ca_pem, crl_pem):
    db_path = tmp_path / 'ca.sqlite'
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE certificate_authority '
                 '(serial, cn, expiry_date, issuer, revocation_date, ignored_at)')
    conn.execute('CREATE TABLE external_certificate (serial, cn, expiry_date, issuer, status)')
    conn.close()

    fresh = {'last_modified': aws_lambda.now}
    return aws_lambda.run_tests(
        {**fresh, 'content': ca_pem},
        {**fresh, 'content': crl_pem},
        {**fresh, 'path': str(db_path)},
    )


@pytest.mark.parametrize('kind', ['rsa', 'p256', 'p384'])
def test_crl_signed_by_ca_verifies(aws_lambda, tmp_path, kind):
    ca_pem, crl_pem = make_pem_ca_and_crl(kind, aws_lambda.now)

    msg, warning = run_checks(aws_lambda, tmp_path, ca_pem, crl_pem)

    assert 'CRL is valid and signature is correct' in msg
    assert not warning


@pytest.mark.parametrize('kind', ['rsa', 'p256'])
def test_crl_signed_by_another_key_fails(aws_lambda, tmp_path, kind):
    ca_pem, crl_pem = make_pem_ca_and_crl(kind, aws_lambda.now, crl_signer=make_key(kind))

    msg, warning = run_checks(aws_lambda, tmp_path, ca_pem, crl_pem)

    assert 'CRL validation failed: signature does not match the CA certificate' in msg
    assert warning


def test_crl_expiring_soon_warns(aws_lambda, tmp_path):
    ca_pem, crl_pem = make_pem_ca_and_crl('rsa', aws_lambda.now, crl_expires_in=timedelta(days=3))

    msg, warning = run_checks(aws_lambda, tmp_path, ca_pem, crl_pem)

    assert 'CRL will expire soon [3 days, 0 hours, 0 minutes]' in msg
    assert warning


def test_expired_crl_is_reported_not_raised(aws_lambda, tmp_path):
    ca_pem, crl_pem = make_pem_ca_and_crl('p256', aws_lambda.now, crl_expires_in=-timedelta(days=2))

    msg, warning = run_checks(aws_lambda, tmp_path, ca_pem, crl_pem)

    assert 'CRL Next Update is in the past [-2 days, 0 hours, 0 minutes]' in msg
    assert warning


@pytest.mark.parametrize('offset, expected', [
    (timedelta(days=2, hours=3, minutes=4), (2, 3, 4, '2 days, 3 hours, 4 minutes')),
    (-timedelta(days=2, hours=3, minutes=4), (-2, -3, -4, '-2 days, 3 hours, 4 minutes')),
    (-timedelta(minutes=5), (0, 0, -5, '-0 days, 0 hours, 5 minutes')),
])
def test_timestamp_until(aws_lambda, offset, expected):
    until = aws_lambda.timestamp_until(aws_lambda.now + offset)

    assert (until['days'], until['hours'], until['minutes'], until['friendly']) == expected
