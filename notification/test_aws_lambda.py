#!/usr/bin/env python3
"""
#
# test_aws_lambda.py - Offline unit tests for the notification Lambda's checks
#
# Run with `python -m pytest notification/test_aws_lambda.py`. No AWS, S3 or
# Slack calls: keys, the CA certificate and the CRL are generated in-test.
#
"""

import io
import os
import sqlite3
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError
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


def make_ca(kind, now):
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
    return key, ca_cert


def make_crl_pem(kind, key, ca_cert, this_update, next_update, number=None, signer=None):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    if number is not None:
        builder = (
            builder
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        )
    crl = builder.sign(signer or key, hashes.SHA384() if kind == 'p384' else hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode()


def make_pem_ca_and_crl(kind, now, crl_expires_in=timedelta(days=30), crl_signer=None):
    key, ca_cert = make_ca(kind, now)
    next_update = now + crl_expires_in
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        make_crl_pem(kind, key, ca_cert, next_update - timedelta(days=30), next_update, signer=crl_signer),
    )


def make_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE certificate_authority '
                 '(serial, cn, expiry_date, issuer, revocation_date, ignored_at)')
    conn.execute('CREATE TABLE external_certificate (serial, cn, expiry_date, issuer, status)')
    conn.close()


def run_checks(aws_lambda, tmp_path, ca_pem, crl_pem):
    db_path = tmp_path / 'checks.sqlite'
    make_db(db_path)

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


class FakeS3:
    def __init__(self, now, objects, put_error=None):
        self.now = now
        self.objects = objects
        self.put_error = put_error
        self.puts = []

    def missing(self, operation):
        return ClientError({'Error': {'Code': 'NoSuchKey'}}, operation)

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise self.missing('GetObject')
        return {'Body': io.BytesIO(self.objects[(Bucket, Key)]), 'LastModified': self.now}

    def download_file(self, bucket, key, path):
        with open(path, 'wb') as f:
            f.write(self.get_object(Bucket=bucket, Key=key)['Body'].read())

    def head_object(self, Bucket, Key):
        return {'LastModified': self.now}

    def put_object(self, Bucket, Key, Body):
        if self.put_error:
            raise ClientError({'Error': {'Code': self.put_error}}, 'PutObject')
        self.objects[(Bucket, Key)] = Body
        self.puts.append(Key)


@pytest.fixture
def run_lambda(aws_lambda, monkeypatch, tmp_path):
    """Run lambda_handler against an in-process S3; returns (message, warning, fake S3)."""
    for var, value in (('private_bucket', 'private'), ('db_key', 'ca.sqlite'),
                       ('public_bucket', 'public'), ('ca_cert_key', 'ca.crt'), ('crl_key', 'crl.pem'),
                       ('local_db_path', str(tmp_path / 'local.sqlite'))):
        monkeypatch.setattr(aws_lambda, var, value)

    db_path = tmp_path / 'ca.sqlite'
    make_db(db_path)

    def run(ca_pem, crl_pem, batch_pem=None, put_error=None):
        objects = {
            ('private', 'ca.sqlite'): db_path.read_bytes(),
            ('public', 'ca.crt'): ca_pem.encode(),
            ('public', 'crl.pem'): crl_pem.encode(),
        }
        if batch_pem is not None:
            objects[('private', 'pending-crl/crl-batch.pem')] = batch_pem.encode()
        s3 = FakeS3(aws_lambda.now, objects, put_error)
        sent = {}
        monkeypatch.setattr(aws_lambda.boto3, 'client', lambda service: s3)
        monkeypatch.setattr(aws_lambda, 'send_slack_notification',
                            lambda user, msg, url, warning: sent.update(msg=msg, warning=warning) or 200)
        aws_lambda.lambda_handler({}, None)
        return sent['msg'], sent['warning'], s3

    return run


def make_batch(kind, key, ca_cert, t0, first_number=0, signer_for=None):
    """Batch as the core writes it: 5 CRLs, 7 days apart, each valid 10 days."""
    return ''.join(
        make_crl_pem(kind, key, ca_cert, t0 + timedelta(days=7 * i), t0 + timedelta(days=7 * i + 10),
                     number=first_number + i, signer=signer_for(i) if signer_for else None)
        for i in range(5)
    )


def ca_and_batch(aws_lambda, kind, t0_days_ago, published_number=0, **batch_args):
    key, ca_cert = make_ca(kind, aws_lambda.now)
    t0 = aws_lambda.now - timedelta(days=t0_days_ago)
    published = make_crl_pem(kind, key, ca_cert, t0, t0 + timedelta(days=10), number=published_number)
    return (ca_cert.public_bytes(serialization.Encoding.PEM).decode(), published,
            make_batch(kind, key, ca_cert, t0, **batch_args))


def published_number(s3):
    crl = x509.load_pem_x509_crl(s3.objects[('public', 'crl.pem')])
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


@pytest.mark.parametrize('error_code', ['NoSuchKey', 'AccessDenied'])
def test_no_batch_behaves_as_before(aws_lambda, run_lambda, tmp_path, monkeypatch, error_code):
    ca_pem, crl_pem = make_pem_ca_and_crl('p256', aws_lambda.now, crl_expires_in=timedelta(days=5))
    monkeypatch.setattr(FakeS3, 'missing',
                        lambda self, operation: ClientError({'Error': {'Code': error_code}}, operation))

    msg, warning, s3 = run_lambda(ca_pem, crl_pem)

    assert (msg, warning) == run_checks(aws_lambda, tmp_path, ca_pem, crl_pem)
    assert 'CRL will expire soon' in msg
    assert s3.puts == []


@pytest.mark.parametrize('kind', ['rsa', 'p256', 'p384'])
def test_latest_due_crl_is_released(aws_lambda, run_lambda, kind):
    ca_pem, published, batch = ca_and_batch(aws_lambda, kind, t0_days_ago=15)

    msg, warning, s3 = run_lambda(ca_pem, published, batch)

    assert s3.puts == ['crl.pem']
    assert published_number(s3) == 2
    assert 'Releasing CRL #2' in msg
    assert '2 unreleased CRLs' in msg
    assert 'CRL is valid and signature is correct' in msg
    assert not warning


@pytest.mark.parametrize('published', [1, 3, 40])
def test_published_crl_is_never_rolled_back(aws_lambda, run_lambda, published):
    ca_pem, published_pem, batch = ca_and_batch(aws_lambda, 'p256', t0_days_ago=8,
                                                published_number=published)

    msg, warning, s3 = run_lambda(ca_pem, published_pem, batch)

    assert s3.puts == []
    assert f'Published CRL #{published} is current' in msg


def test_nothing_is_released_before_the_first_crl_is_due(aws_lambda, run_lambda):
    ca_pem, published, batch = ca_and_batch(aws_lambda, 'rsa', t0_days_ago=-1, first_number=1)

    msg, warning, s3 = run_lambda(ca_pem, published, batch)

    assert s3.puts == []
    assert 'No batch CRL is due yet' in msg


@pytest.mark.parametrize('kind', ['rsa', 'p256'])
def test_batch_with_a_bad_signature_is_refused(aws_lambda, run_lambda, kind):
    impostor = make_key(kind)
    ca_pem, published, batch = ca_and_batch(aws_lambda, kind, t0_days_ago=8,
                                            signer_for=lambda i: impostor if i == 1 else None)

    msg, warning, s3 = run_lambda(ca_pem, published, batch)

    assert s3.puts == []
    assert 'CRL batch refused: CRL 1 not signed by the CA certificate' in msg
    assert warning


def test_garbled_batch_is_refused(aws_lambda, run_lambda):
    ca_pem, published, _ = ca_and_batch(aws_lambda, 'p256', t0_days_ago=8)

    msg, warning, s3 = run_lambda(ca_pem, published, '-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n')

    assert s3.puts == []
    assert 'CRL batch refused' in msg
    assert warning


def test_cover_warns_under_two_unreleased(aws_lambda, run_lambda):
    ca_pem, published, batch = ca_and_batch(aws_lambda, 'p256', t0_days_ago=22)

    msg, warning, s3 = run_lambda(ca_pem, published, batch)

    assert published_number(s3) == 3
    assert 'Only 1 unreleased CRLs left, cover ends in [16 days, 0 hours, 0 minutes]' in msg
    assert warning


def test_released_crl_does_not_warn_as_expiring_in_batch_mode(aws_lambda, run_lambda):
    ca_pem, published, batch = ca_and_batch(aws_lambda, 'p256', t0_days_ago=3)

    msg, warning, s3 = run_lambda(ca_pem, published, batch)

    assert s3.puts == []
    assert 'CRL Next Update is in the future [7 days, 0 hours, 0 minutes]' in msg
    assert not warning


def test_failed_release_warns_and_overdue_crl_expires_soon(aws_lambda, run_lambda):
    ca_pem, published, batch = ca_and_batch(aws_lambda, 'p256', t0_days_ago=8)

    msg, warning, s3 = run_lambda(ca_pem, published, batch, put_error='AccessDenied')

    assert 'Publishing the released CRL failed' in msg
    assert 'CRL will expire soon [2 days, 0 hours, 0 minutes]' in msg
    assert warning
