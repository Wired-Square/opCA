#!/usr/bin/env python3
"""
#
# test_acme_client.py - Tests for acme-client.sh
#
# Run with `python -m pytest contrib/acme-client`. The offline tests put a fake lego on PATH and
# run the entrypoint under each POSIX shell found. With OPCA_ACME_CLIENT_DOCKER_TEST=1 the image
# also orders a certificate from Pebble, on an internal Docker network torn down afterwards.
#
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from cryptography import x509

HERE = Path(__file__).parent
SCRIPT = HERE / 'acme-client.sh'
SHELLS = [s for s in ('sh', 'dash') if shutil.which(s)]

FAKE_LEGO = f'''#!{sys.executable}
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
log = Path(os.environ['FAKE_LEGO_LOG'])
calls = log.read_text().splitlines() if log.exists() else []
with log.open('a') as f:
    f.write(json.dumps({{'args': args, 'env': dict(os.environ)}}) + '\\n')
if len(calls) < int(os.environ.get('FAKE_LEGO_FAILS', '0')):
    sys.exit(3)
first = args[args.index('--domains') + 1].replace('*', '_')
cert = Path(args[args.index('--path') + 1], 'certificates', first + '.crt')
if 'run' in args or os.environ.get('FAKE_LEGO_RENEWS') == '1':
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text(f'certificate {{len(calls)}}\\n')
'''


@pytest.fixture
def lego(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'lego'
    fake.write_text(FAKE_LEGO)
    fake.chmod(0o755)
    return bin_dir, tmp_path / 'lego.log'


@pytest.fixture
def env(tmp_path, lego):
    ca = tmp_path / 'ca.pem'
    ca.write_text('root\n')
    return {
        'PATH': f'{lego[0]}:{os.environ["PATH"]}',
        'FAKE_LEGO_LOG': str(lego[1]),
        'ACME_SERVER': 'https://broker.example:8443/acme/directory',
        'ACME_EMAIL': 'ops@example.com',
        'ACME_DOMAINS': 'app.example.com',
        'ACME_CHALLENGE': 'http',
        'ACME_CA_BUNDLE': str(ca),
        'ACME_DATA': str(tmp_path / 'data'),
        'ACME_ONCE': '1',
    }


def calls(lego):
    log = lego[1]
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def run(env, shell='sh'):
    return subprocess.run([shell, str(SCRIPT)], env=env, capture_output=True, text=True,
                          timeout=30)


def cert(env, name='app.example.com'):
    return Path(env['ACME_DATA'], 'certificates', f'{name}.crt')


def hook_marker(tmp_path, env):
    marker = tmp_path / 'hooked'
    env['ACME_HOOK'] = f'echo "$ACME_CERT $ACME_KEY" >> {marker}'
    return marker


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('challenge, flags', [
    ('http', ['--http']),
    ('tls', ['--tls']),
    ('dns:cloudflare', ['--dns', 'cloudflare']),
])
def test_first_run_orders_with_the_challenge(env, lego, shell, challenge, flags):
    env.update(ACME_CHALLENGE=challenge, ACME_DOMAINS='app.example.com, *.app.example.com',
               CLOUDFLARE_DNS_API_TOKEN='token')

    result = run(env, shell)

    assert result.returncode == 0, result.stderr
    [call] = calls(lego)
    assert call['args'] == [
        '--server', env['ACME_SERVER'], '--email', 'ops@example.com', '--accept-tos',
        '--path', env['ACME_DATA'], '--key-type', 'ec256',
        '--domains', 'app.example.com', '--domains', '*.app.example.com', *flags, 'run',
    ]
    assert call['env']['LEGO_CA_CERTIFICATES'] == env['ACME_CA_BUNDLE']
    assert call['env']['CLOUDFLARE_DNS_API_TOKEN'] == 'token'


def test_options_reach_lego(env, lego):
    env.update(ACME_KEY_TYPE='rsa2048', ACME_ARGS='--http.port :8080  --http-timeout 30')

    assert run(env).returncode == 0
    args = calls(lego)[0]['args']
    assert args[args.index('--key-type') + 1] == 'rsa2048'
    assert args[-6:] == ['--http', '--http.port', ':8080', '--http-timeout', '30', 'run']


def test_a_new_certificate_runs_the_hook(tmp_path, env):
    marker = hook_marker(tmp_path, env)

    result = run(env)

    assert result.returncode == 0, result.stderr
    key = cert(env).with_suffix('.key')
    assert marker.read_text() == f'{cert(env)} {key}\n'


def test_a_wildcard_first_domain_names_the_files_with_an_underscore(tmp_path, env):
    env['ACME_DOMAINS'] = '*.app.example.com'
    marker = hook_marker(tmp_path, env)

    assert run(env).returncode == 0
    assert cert(env, '_.app.example.com').exists()
    assert marker.read_text().startswith(f'{cert(env, "_.app.example.com")} ')


@pytest.mark.parametrize('shell', SHELLS)
def test_an_existing_certificate_is_renewed(tmp_path, env, lego, shell):
    cert(env).parent.mkdir(parents=True)
    cert(env).write_text('old\n')
    env.update(ACME_RENEW_DAYS='20', FAKE_LEGO_RENEWS='1')
    marker = hook_marker(tmp_path, env)

    result = run(env, shell)

    assert result.returncode == 0, result.stderr
    assert calls(lego)[0]['args'][-3:] == ['renew', '--days', '20']
    assert marker.exists()


def test_a_certificate_not_yet_due_skips_the_hook(tmp_path, env, lego):
    cert(env).parent.mkdir(parents=True)
    cert(env).write_text('current\n')
    marker = hook_marker(tmp_path, env)

    result = run(env)

    assert result.returncode == 0, result.stderr
    assert calls(lego)[0]['args'][-3:] == ['renew', '--days', '10']
    assert cert(env).read_text() == 'current\n'
    assert not marker.exists()


def test_a_lego_failure_fails_the_pass_without_the_hook(tmp_path, env):
    env['FAKE_LEGO_FAILS'] = '1'
    marker = hook_marker(tmp_path, env)

    result = run(env)

    assert result.returncode == 3
    assert not marker.exists()


def test_a_failed_hook_fails_the_pass(env):
    env['ACME_HOOK'] = 'exit 4'

    result = run(env)

    assert result.returncode == 1
    assert 'ACME_HOOK failed: exit 4' in result.stderr


@pytest.mark.parametrize('name', [
    'ACME_SERVER', 'ACME_EMAIL', 'ACME_DOMAINS', 'ACME_CHALLENGE', 'ACME_CA_BUNDLE',
])
def test_a_missing_required_variable_is_refused(env, lego, name):
    del env[name]

    result = run(env)

    assert result.returncode == 2
    assert f'{name} is required' in result.stderr
    assert not calls(lego)


@pytest.mark.parametrize('change, expected', [
    ({'ACME_CHALLENGE': 'dns-01'}, "ACME_CHALLENGE must be http, tls or dns:<lego provider>"),
    ({'ACME_CHALLENGE': 'dns:'}, 'ACME_CHALLENGE must be'),
    ({'ACME_CA_BUNDLE': '/nonexistent/ca.pem'}, 'is not a readable file'),
    ({'ACME_DOMAINS': ' , '}, 'ACME_DOMAINS names no domain'),
    ({'ACME_RENEW_DAYS': 'ten'}, "ACME_RENEW_DAYS must be a whole number, not 'ten'"),
    ({'ACME_CHECK_INTERVAL': '12h'}, 'ACME_CHECK_INTERVAL must be a whole number'),
    ({'ACME_RETRY_INTERVAL': '-1'}, 'ACME_RETRY_INTERVAL must be a whole number'),
])
def test_a_bad_setting_is_refused(env, lego, change, expected):
    env.update(change)

    result = run(env)

    assert result.returncode == 2
    assert expected in result.stderr
    assert not calls(lego)


def wait_for_calls(lego, count):
    deadline = time.monotonic() + 10
    while len(calls(lego)) < count:
        assert time.monotonic() < deadline, f'waited for {count} lego calls'
        time.sleep(0.05)


@pytest.mark.parametrize('shell', SHELLS)
def test_the_loop_retries_a_failure_then_stops_promptly_on_sigterm(env, lego, shell):
    del env['ACME_ONCE']
    env.update(FAKE_LEGO_FAILS='1', ACME_RETRY_INTERVAL='0', ACME_CHECK_INTERVAL='600')
    proc = subprocess.Popen([shell, str(SCRIPT)], env=env, stderr=subprocess.PIPE, text=True)
    try:
        wait_for_calls(lego, 2)
        time.sleep(0.3)
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=3) == 143
    finally:
        proc.kill()
    assert [c['args'][-1] for c in calls(lego)] == ['run', 'run']
    assert 'trying again in 0 s' in proc.stderr.read()


IMAGE = 'opca-acme-client:test'
PEBBLE = 'ghcr.io/letsencrypt/pebble:2.8.0'


def docker(*args, timeout=120, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout,
                          check=check)


@pytest.fixture
def network():
    name = f'opca-acme-client-{uuid.uuid4().hex[:8]}'
    docker('build', '-q', '-t', IMAGE, str(HERE), timeout=300)
    docker('network', 'create', '--internal', name)
    containers = []
    try:
        yield name, containers
    finally:
        for container in containers:
            docker('rm', '-f', container, check=False)
        docker('network', 'rm', name, check=False)
        docker('image', 'rm', IMAGE, check=False)


@pytest.mark.skipif(os.environ.get('OPCA_ACME_CLIENT_DOCKER_TEST') != '1',
                    reason='set OPCA_ACME_CLIENT_DOCKER_TEST=1 to run against Pebble in Docker')
def test_the_image_issues_from_pebble_and_stops_on_sigterm(tmp_path, network):
    net, containers = network
    pebble = f'{net}-pebble'
    containers.append(pebble)
    docker('run', '-d', '--name', pebble, '--network', net, '--network-alias', 'pebble',
           '-e', 'PEBBLE_VA_NOSLEEP=1', '-e', 'PEBBLE_WFE_NONCEREJECT=0', PEBBLE)
    docker('cp', f'{pebble}:/test/certs/pebble.minica.pem', str(tmp_path / 'ca.pem'))
    data = tmp_path / 'data'
    data.mkdir()
    client = [
        '--network', net, '--network-alias', 'client.test',
        '-v', f'{tmp_path / "ca.pem"}:/etc/acme/ca.pem:ro', '-v', f'{data}:/data',
        '-e', 'ACME_SERVER=https://pebble:14000/dir', '-e', 'ACME_EMAIL=ops@example.com',
        '-e', 'ACME_DOMAINS=client.test', '-e', 'ACME_CHALLENGE=http',
        '-e', 'ACME_CA_BUNDLE=/etc/acme/ca.pem', '-e', 'ACME_ARGS=--http.port :5002',
        '-e', 'ACME_HOOK=echo "$ACME_CERT" >> /data/hooked',
        # Below Pebble's 6-day profile, which it picks at random for an order with none.
        '-e', 'ACME_RENEW_DAYS=1',
    ]

    def once(role):
        containers.append(f'{net}-{role}')
        return docker('run', '--rm', '--name', f'{net}-{role}', '-e', 'ACME_ONCE=1', *client,
                      IMAGE, check=False)

    issued = once('issue')
    assert issued.returncode == 0, issued.stderr
    leaf = x509.load_pem_x509_certificate((data / 'certificates' / 'client.test.crt').read_bytes())
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ['client.test']

    not_due = once('not-due')
    assert not_due.returncode == 0, not_due.stderr
    assert (data / 'hooked').read_text() == '/data/certificates/client.test.crt\n'

    looping = f'{net}-client'
    containers.append(looping)
    docker('run', '-d', '--name', looping, *client, IMAGE)
    deadline = time.monotonic() + 60
    while 'no renewal' not in docker('logs', looping).stderr:
        assert time.monotonic() < deadline, 'the looping client never checked its certificate'
        time.sleep(0.5)
    started = time.monotonic()
    docker('stop', '-t', '10', looping)
    assert time.monotonic() - started < 5
    assert docker('inspect', '-f', '{{.State.ExitCode}}', looping).stdout.strip() == '143'
