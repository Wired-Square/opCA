#!/usr/bin/env python3
"""
#
# aws_lambda_test.py - A local test script for the AWS Lambda notification function
#
# Credentials come from the 1Password item selected in opCA (CA > Stores, or
# `opca aws use`), read with `op item get`. The deployed Lambda uses its
# execution role instead and needs none of this.
#
# Source environment.sh before running - aws_lambda reads its configuration
# from the environment at import time.
#
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Written by opca-core/src/settings.rs.
SETTINGS_FILE = 'settings.json'
DEFAULT_ACCOUNT_KEY = 'default'

# 1Password field label -> environment variable boto3 reads. Labels are
# compared lower-case and must stay in step with parse_aws_item_json() in
# opca-core/src/services/storage/mod.rs, which accepts either region label.
ENV_BY_LABEL = {
    'access key id': 'AWS_ACCESS_KEY_ID',
    'secret access key': 'AWS_SECRET_ACCESS_KEY',
    'session token': 'AWS_SESSION_TOKEN',
    'default region': 'AWS_DEFAULT_REGION',
    'region': 'AWS_DEFAULT_REGION',
}
REQUIRED_ENV = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY')


def settings_path():
    """Locate opCA's per-user settings file, mirroring Rust's dirs::config_dir()."""
    if sys.platform == 'darwin':
        config_dir = Path.home() / 'Library' / 'Application Support'
    else:
        config_dir = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config'))

    return config_dir / 'opca' / SETTINGS_FILE


def selected_item():
    """Return (account, item_id) for the AWS credential selected in opCA."""
    path = settings_path()

    try:
        settings = json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(
            f'No opCA settings at {path}.\n'
            'Select an AWS credential first: opCA > CA > Stores, or `opca aws use <item>`.'
        )

    items = settings.get('aws_credential_items') or {}
    if not items:
        raise SystemExit(
            f'No AWS credential selected in {path}.\n'
            'Select one first: opCA > CA > Stores, or `opca aws use <item>`.'
        )

    account = os.environ.get('OPCA_ACCOUNT', '').strip().lower()
    if account:
        if account not in items:
            raise SystemExit(
                f'No AWS credential selected for {account}. '
                f'Available: {", ".join(sorted(items))}'
            )
    elif len(items) == 1:
        account = next(iter(items))
    else:
        raise SystemExit(
            'Several accounts have a credential selected — set OPCA_ACCOUNT to one of: '
            f'{", ".join(sorted(items))}'
        )

    return account, items[account]


def load_aws_credentials():
    """Read the selected 1Password item, keyed by environment variable name."""
    account, item_id = selected_item()

    command = ['op', 'item', 'get', item_id, '--format=json']
    if account != DEFAULT_ACCOUNT_KEY:
        command += ['--account', account]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemExit("The 'op' CLI was not found on PATH.")

    if result.returncode != 0:
        raise SystemExit(f'Could not read item {item_id}: {result.stderr.strip()}')

    env = {}
    for field in json.loads(result.stdout).get('fields', []):
        var = ENV_BY_LABEL.get((field.get('label') or '').lower())
        if var and field.get('value'):
            env[var] = field['value']

    missing = set(REQUIRED_ENV) - env.keys()
    if missing:
        raise SystemExit(f'Item {item_id} is missing: {", ".join(sorted(missing))}')

    return env


def apply_aws_credentials():
    """Export the selected credential into the environment for boto3."""
    env = load_aws_credentials()

    # The CA's region lives in its database, so only fill the gap when the
    # environment has not already set one.
    if os.environ.get('AWS_DEFAULT_REGION'):
        env.pop('AWS_DEFAULT_REGION', None)

    for var, value in env.items():
        os.environ[var] = value
        print(f'{var} is now set')


class Context:
    def __init__(self):
        self.function_name = "test_lambda"
        self.memory_limit_in_mb = 128
        self.invoked_function_arn = "arn:aws:lambda:ap-southeast-1:123456789012:function:test_lambda"
        self.aws_request_id = "test-request-id"


if __name__ == '__main__':
    from aws_lambda import lambda_handler

    event = {
        "key1": "value1",
        "key2": "value2"
    }

    apply_aws_credentials()
    print(lambda_handler(event, Context()))
