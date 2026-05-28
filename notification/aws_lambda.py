#!/usr/bin/env python3
"""
#
# aws_lambda.py - A notification script for AWS Lambda
#
"""

import boto3
import os
import json
import sqlite3
import urllib3
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone


now = datetime.now(timezone.utc)
days = int(os.environ.get('DAYS'))
crl_days = int(os.environ.get('CRL_DAYS'))
private_bucket = os.environ.get('PRIVATE_BUCKET')
db_key = os.environ.get('DB_KEY')
public_bucket = os.environ.get('PUBLIC_BUCKET')
ca_cert_key = os.environ.get('CA_CERT_KEY')
crl_key = os.environ.get('CRL_KEY')
local_db_path = os.environ.get('LOCAL_DB_PATH')
local_crl_path = os.environ.get('LOCAL_CRL_PATH')
slack_user = os.environ.get('SLACK_USER')
slack_url = os.environ.get('SLACK_URL')


def ca_database_handler(file, query):
    conn = sqlite3.connect(file)
    cursor = conn.cursor()

    cursor.execute(query)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return rows

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
            msg += f'    [{serial}] {prefix}{cn} - Expiries in {timestamp_until(expiry_date)['friendly']}\n'

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

def run_tests(ca_cert_data, crl_data, db_data):
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
        ca_cert.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),  # or use crl.signature_hash_algorithm.padding if available
            crl.signature_hash_algorithm,
        )

        msg += concat_msg('  ✅ CRL is valid and signature is correct')

    except Exception as e:
        warning = True
        msg += concat_msg(f'  ❌ *CRL validation failed: {e}*')

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
    elif crl_next_update - now <= timedelta(crl_days):
        msg += concat_msg(f'  ⚠️ *CRL will expire soon [{crl_expiry_friendly}]')
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

def timestamp_diff(last_modified):
    """
    Return the number of days, hours and minutes between now and a last_modified timestamp

    Args:
        last_modified (datetime.datetime)

    Returns:
        dict: {
            "days": int,
            "hours": int,
            "minutes": int,
            "friendly": str
        }
    """
    age = now - last_modified.replace(tzinfo=timezone.utc)

    total_seconds = int(age.total_seconds())

    age_hours, remainder = divmod(total_seconds - age.days * 86400, 3600)
    age_minutes = remainder // 60

    friendly_age = f'{age.days} days, {age_hours} hours, {age_minutes} minutes'

    return {
        'days': age.days,
        'hours': age_hours,
        'minutes': age_minutes,
        'friendly': friendly_age,
    }

def timestamp_until(expiry_time):
    """
    Return the number of days, hours and minutes until an expiry timestamp

    Args:
        expiry_time (datetime.datetime)

    Returns:
        dict: {
            "days": int,
            "hours": int,
            "minutes": int,
            "friendly": str
        }
    """
    delta = expiry_time.replace(tzinfo=timezone.utc) - now

    total_seconds = int(delta.total_seconds())

    sign = ''
    if total_seconds < 0:
        total_seconds = abs(total_seconds)
        sign = '-'

    age_days = delta.days
    if age_days < 0:
        days = abs(days)

    age_hours, remainder = divmod(total_seconds - age_days * 86400, 3600)
    age_minutes = remainder // 60

    friendly_age = f'{sign}{age_days} days, {age_hours} hours, {age_minutes} minutes'

    return {
        'days': age_days,
        'hours': age_hours,
        'minutes': age_minutes,
        'friendly': friendly_age,
    }

def lambda_handler(event, context):
    db_data = get_s3_item(bucket=private_bucket, key=db_key, path=local_db_path)
    ca_cert_data = get_s3_item(bucket=public_bucket, key=ca_cert_key)
    crl_data = get_s3_item(bucket=public_bucket, key=crl_key)

    msg, warning = run_tests(ca_cert_data, crl_data, db_data)

    notification_status = send_slack_notification(slack_user, msg, slack_url, warning)

    return {
        'statusCode': notification_status,
    }
