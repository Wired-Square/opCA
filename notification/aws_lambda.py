#!/usr/bin/env python3
"""
#
# aws_lambda.py - A notification script for AWS Lambda
#
"""

import boto3
import os
import json
import re
import sqlite3
import urllib3
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timedelta, timezone


now = datetime.now(timezone.utc)
days = int(os.environ.get('DAYS'))
crl_days = int(os.environ.get('CRL_DAYS'))
private_bucket = os.environ.get('PRIVATE_BUCKET')
db_key = os.environ.get('DB_KEY')
public_bucket = os.environ.get('PUBLIC_BUCKET')
ca_cert_key = os.environ.get('CA_CERT_KEY')
crl_key = os.environ.get('CRL_KEY')
pending_crl_key = os.environ.get('PENDING_CRL_KEY', 'pending-crl/crl-batch.pem')
local_db_path = os.environ.get('LOCAL_DB_PATH')
local_crl_path = os.environ.get('LOCAL_CRL_PATH')
slack_user = os.environ.get('SLACK_USER')
slack_url = os.environ.get('SLACK_URL')

PEM_CRL = re.compile(r'-----BEGIN X509 CRL-----.+?-----END X509 CRL-----', re.DOTALL)
# Batch CRLs are replaced 3 days (W - P) before nextUpdate; less left means a release is overdue.
BATCH_CRL_WARN_DAYS = 3


def ca_database_handler(file, query):
    conn = sqlite3.connect(file)
    cursor = conn.cursor()

    cursor.execute(query)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows

def crl_batch_enabled(db_path):
    try:
        rows = ca_database_handler(db_path, 'SELECT crl_batch_enabled FROM config')
    except sqlite3.OperationalError:
        # A dump older than schema v15 has no flag: batches off.
        return False
    return bool(rows and rows[0][0])

def concat_msg(msg):
    print(msg)

    return f'{msg}\n'

def find_expiring_certificates(certificates, days):
    expiring_certs = {
        'expiring': False,
        'certs': {},
        'msg': ''
        }
    delta = timedelta(days)
    msg = ''

    for row in certificates:
        serial, cn, expiry_str = row[0], row[1], row[2]
        issuer = row[3] if len(row) > 3 else None
        expiry_date = datetime.strptime(expiry_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

        if now <= expiry_date <= now + delta:
            expiring_certs['expiring'] = True
            expiring_certs['certs'][serial] = {'cn': cn, 'expiry': expiry_str}
            prefix = f'[EXT:{issuer}] ' if issuer else ''
            msg += f'    [{serial}] {prefix}{cn} - Expires in {timestamp_until(expiry_date)['friendly']}\n'

    expiring_certs['msg'] = msg

    return expiring_certs

def get_s3_item(bucket, key, path=None, encoding='utf-8'):
    """
    Download a file from S3 to local path or read its content as a string.

    Args:
        bucket (str): S3 bucket name.
        key (str): S3 object key.
        path (str, optional): Local file path to download to. If None, reads content as string.
        encoding (str, optional): Encoding used when decoding file content. Defaults to 'utf-8'.

    Returns:
        dict: {
            "path": str (if file is downloaded to local filesystem),
            "content": str (if file content is retrieved),
            "last_modified": datetime
        }
    """
    s3 = boto3.client('s3')

    try:
        if path is not None:
            s3.download_file(bucket, key, path)
            print(f'File [{bucket}/{key}] downloaded to: {path}')
            metadata = s3.head_object(Bucket=bucket, Key=key)
            return {
                'path': path,
                'last_modified': metadata['LastModified']
            }
        else:
            response = s3.get_object(Bucket=bucket, Key=key)
            file_content = response['Body'].read().decode(encoding) 
            print(f'File [{bucket}/{key}] content retrieved from S3')
            return {
                'content': file_content,
                'last_modified': response['LastModified']
            }
    
    except ClientError as e:
        print(f'Failed to retrieve S3 object: {e}')
        raise

def get_pending_crl_batch():
    try:
        return get_s3_item(bucket=private_bucket, key=pending_crl_key)['content']
    except ClientError as e:
        # Without s3:ListBucket a missing key reads as AccessDenied, not NoSuchKey.
        if e.response['Error']['Code'] in ('NoSuchKey', 'AccessDenied'):
            return None
        raise

def crl_number(crl):
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None

def is_signed_by(crl, public_key):
    try:
        return crl.is_signature_valid(public_key)
    except Exception:
        return False

def release_due_crl(ca_cert_pem, batch_pem, published_crl_pem):
    """
    Return (PEM to publish or None, message, warning): the latest due batch CRL if it is
    newer than the published one. Any unsigned or unnumbered CRL refuses the whole batch.
    """
    msg = concat_msg('\n*CRL Batch*')
    ca_public_key = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8')).public_key()

    try:
        batch = [x509.load_pem_x509_crl(pem.encode('utf-8')) for pem in PEM_CRL.findall(batch_pem)]
    except ValueError as e:
        return None, msg + concat_msg(f'  ❌ *CRL batch refused: {e}*'), True
    if not batch:
        return None, msg + concat_msg('  ❌ *CRL batch refused: it holds no CRLs*'), True

    bad = [str(crl_number(crl)) for crl in batch
           if crl_number(crl) is None or not is_signed_by(crl, ca_public_key)]
    if bad:
        return None, msg + concat_msg(
            f'  ❌ *CRL batch refused: CRL {", ".join(bad)} not signed by the CA certificate or unnumbered*'), True

    published = crl_number(x509.load_pem_x509_crl(published_crl_pem.encode('utf-8')))
    published = -1 if published is None else published
    due = [crl for crl in batch if crl.last_update_utc <= now]
    release = None

    if not due:
        msg += concat_msg('  ✅ No batch CRL is due yet')
    else:
        latest = max(due, key=lambda crl: crl.last_update_utc)
        if crl_number(latest) > published:
            release = latest.public_bytes(Encoding.PEM).decode('utf-8')
            msg += concat_msg(f'  ✅ Releasing CRL #{crl_number(latest)}')
        else:
            msg += concat_msg(f'  ✅ Published CRL #{published} is current')

    unreleased = len(batch) - len(due)
    cover = timestamp_until(max(crl.next_update_utc for crl in batch))['friendly']
    warning = unreleased < 2
    if warning:
        msg += concat_msg(f'  ⚠️ *Only {unreleased} unreleased CRLs left, cover ends in [{cover}]. '
                          'Re-sign the batch in opCA.*')
    else:
        msg += concat_msg(f'  ✅ {unreleased} unreleased CRLs, cover ends in [{cover}]')

    return release, msg, warning

def run_tests(ca_cert_data, crl_data, db_data, crl_warn_days=None):
    ca_cert_pem = ca_cert_data['content']
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'), backend=default_backend())

    crl_pem = crl_data['content']
    crl_file_age = timestamp_diff(crl_data['last_modified'])
    crl = x509.load_pem_x509_crl(crl_pem.encode('utf-8'), backend=default_backend())
    crl_next_update = crl.next_update_utc
    crl_expiry_friendly = timestamp_until(crl_next_update)['friendly']

    cadb_file_age = timestamp_diff(db_data['last_modified'])
    # Skip ignored certs (ignored_at set): renewed/rekeyed certs are
    # auto-ignored by opCA so the predecessor stops triggering expiry alerts.
    cadb_query = """
        SELECT serial, cn, expiry_date, issuer
        FROM certificate_authority
        WHERE revocation_date IS NULL
          AND ignored_at IS NULL
    """
    rows = ca_database_handler(db_data['path'], cadb_query)

    ext_query = """
        SELECT serial, cn, expiry_date, issuer
        FROM external_certificate
        WHERE status = 'Valid'
    """
    ext_rows = ca_database_handler(db_data['path'], ext_query)

    msg = concat_msg('*CA Database*')
    warning = False

    # CA Database file age check
    if cadb_file_age['days'] > days:
        warning = True
        msg += concat_msg(f'  ⚠️ *CA Database is too old at {cadb_file_age['friendly']}*')
    else:
        msg += concat_msg(f'  ✅ CA Database file age is {cadb_file_age['friendly']}')

    # Check for certificates expiring soon
    expiring_certs = find_expiring_certificates(rows, days)

    num_certs = len(expiring_certs['certs'])

    if expiring_certs['expiring']:
        warning = True
        msg += concat_msg(f'  ⚠️ *[{num_certs}] Certificates expiring in the next {days} days.*\n' +
                          f'{expiring_certs['msg']}')
    else:
        msg += concat_msg(f'  ✅ No certificates expiring in the next {days} days.')

    # Check for external certificates expiring soon
    if ext_rows:
        msg += concat_msg('\n*External Certificates*')
        expiring_ext_certs = find_expiring_certificates(ext_rows, days)
        num_ext_certs = len(expiring_ext_certs['certs'])

        if expiring_ext_certs['expiring']:
            warning = True
            msg += concat_msg(f'  ⚠️ *[{num_ext_certs}] External certificates expiring in the next {days} days.*\n' +
                              f'{expiring_ext_certs['msg']}')
        else:
            msg += concat_msg(f'  ✅ No external certificates expiring in the next {days} days.')

    msg += concat_msg('\n*CA Certificate*')
    # Check CA Certificate validity
    if not (ca_cert.not_valid_before_utc <= now <= ca_cert.not_valid_after_utc):
        warning = True
        msg += concat_msg('  ❌ *CA Certificate is not currently valid*')
    else:
        time_to_expiry = ca_cert.not_valid_after_utc - now

        if time_to_expiry <= timedelta(days=days):
            warning = True
            msg += concat_msg(f'  ⚠️ *CA Certificate is expiring in {days} days*')
        else:
            msg += concat_msg('  ✅ CA Certificate is valid and does not expire soon')

    msg += concat_msg('\n*CRL*')

    # Check CRL signature
    try:
        crl_error = None if crl.is_signature_valid(ca_cert.public_key()) else 'signature does not match the CA certificate'
    except Exception as e:
        crl_error = e

    if crl_error:
        warning = True
        msg += concat_msg(f'  ❌ *CRL validation failed: {crl_error}*')
    else:
        msg += concat_msg('  ✅ CRL is valid and signature is correct')

    # File age check
    if crl_file_age['days'] > days:
        warning = True
        msg += concat_msg(f'  ⚠️ *CRL is too old at {crl_file_age['friendly']}*')
    else:
        msg += concat_msg(f'  ✅ CRL file age is {crl_file_age['friendly']}')

    # CRL validity check
    if crl_next_update < now:
        warning = True
        msg += concat_msg(f'  ❌️ *CRL Next Update is in the past [{crl_expiry_friendly}]*')
    elif crl_next_update - now <= timedelta(crl_days if crl_warn_days is None else crl_warn_days):
        warning = True
        msg += concat_msg(f'  ⚠️ *CRL will expire soon [{crl_expiry_friendly}]*')
    else:
        msg += concat_msg(f'  ✅ CRL Next Update is in the future [{crl_expiry_friendly}]')

    return msg, warning

def send_slack_notification(username, message, webhook_url, warning=False):
    if warning:
        icon = ':warning:'
    else:
        icon = ':robot_face:'

    slack_data = {
        'username': username,
        'icon_emoji': icon,
        'text': message
    }

    http = urllib3.PoolManager()
    response = http.request(
        'POST',
        webhook_url,
        body=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

    print(f"Slack response status: {response.status}")

    return response.status

def split_duration(delta):
    """
    Return a timedelta as whole days, hours and minutes, each carrying its sign

    Returns:
        dict: {
            "days": int,
            "hours": int,
            "minutes": int,
            "friendly": str
        }
    """
    total_seconds = int(delta.total_seconds())
    sign = -1 if total_seconds < 0 else 1
    whole_days, remainder = divmod(abs(total_seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60

    return {
        'days': sign * whole_days,
        'hours': sign * hours,
        'minutes': sign * minutes,
        'friendly': f'{"-" if sign < 0 else ""}{whole_days} days, {hours} hours, {minutes} minutes',
    }

def timestamp_diff(last_modified):
    return split_duration(now - last_modified.replace(tzinfo=timezone.utc))

def timestamp_until(expiry_time):
    return split_duration(expiry_time.replace(tzinfo=timezone.utc) - now)

def lambda_handler(event, context):
    db_data = get_s3_item(bucket=private_bucket, key=db_key, path=local_db_path)
    ca_cert_data = get_s3_item(bucket=public_bucket, key=ca_cert_key)
    crl_data = get_s3_item(bucket=public_bucket, key=crl_key)

    if not crl_batch_enabled(db_data['path']):
        msg, warning = run_tests(ca_cert_data, crl_data, db_data)
    elif (batch_pem := get_pending_crl_batch()) is None:
        msg, warning = run_tests(ca_cert_data, crl_data, db_data)
        msg += concat_msg('\n*CRL Batch*')
        msg += concat_msg(f'  ❌ *CRL batches are on but [{pending_crl_key}] is missing or unreadable*')
        warning = True
    else:
        release, batch_msg, batch_warning = release_due_crl(
            ca_cert_data['content'], batch_pem, crl_data['content'])
        if release:
            try:
                boto3.client('s3').put_object(Bucket=public_bucket, Key=crl_key, Body=release.encode('utf-8'))
                crl_data = {'content': release, 'last_modified': now}
            except ClientError as e:
                batch_warning = True
                batch_msg += concat_msg(f'  ❌ *Publishing the released CRL failed: {e}*')
        msg, warning = run_tests(ca_cert_data, crl_data, db_data, min(crl_days, BATCH_CRL_WARN_DAYS))
        msg += batch_msg
        warning = warning or batch_warning

    notification_status = send_slack_notification(slack_user, msg, slack_url, warning)

    return {
        'statusCode': notification_status,
    }
