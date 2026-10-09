"""Regression tests run without a database, Docker, or model downloads."""
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from starlette.websockets import WebSocketDisconnect
from api import auth, main
from pipeline.suppression import SuppressionEngine


@pytest.fixture(autouse=True)
def configured_auth(monkeypatch):
    monkeypatch.setenv('JWT_SECRET', 'test-only-secret-with-more-than-32-characters')
    monkeypatch.setenv('ENV', 'production')
    monkeypatch.delenv('ALLOW_DEV_LOGIN', raising=False)
    monkeypatch.delenv('AD_SERVER_URL', raising=False)
    monkeypatch.setattr(auth.secrets, 'get_jwt_config', lambda: {})
    monkeypatch.setattr(auth.secrets, 'get_secret', lambda name: {})
    monkeypatch.setattr(main.db, 'pool', None)


def token(roles=None, **claims):
    payload = {'sub': 'tester', 'roles': roles or ['analyst'], 'exp': int(time.time()) + 300}
    payload.update(claims)
    return jwt.encode(payload, 'test-only-secret-with-more-than-32-characters', algorithm='HS256')


def headers(roles=None):
    return {'Authorization': 'Bearer ' + token(roles)}


@pytest.mark.parametrize('path', ['/api/train/status', '/api/stats', '/api/train/run'])
def test_private_endpoints_require_auth(path):
    client = TestClient(main.app)
    method = client.post if path.endswith('/run') else client.get
    assert method(path).status_code == 401
    assert method(path, headers={'Authorization': 'Bearer demo'}).status_code == 401


def test_training_requires_admin():
    assert TestClient(main.app).post('/api/train/run', headers=headers()).status_code == 403


def test_dev_login_explicit_opt_in(monkeypatch):
    client = TestClient(main.app)
    body = {'username': 'analyst', 'password': 'dev'}
    assert client.post('/api/auth/login', json=body).status_code == 401
    monkeypatch.setenv('ENV', 'dev')
    assert client.post('/api/auth/login', json=body).status_code == 401
    monkeypatch.setenv('ALLOW_DEV_LOGIN', 'true')
    result = client.post('/api/auth/login', json=body)
    assert result.status_code == 200
    assert result.json()['roles'] == ['analyst']
    credentials = auth.HTTPAuthorizationCredentials(scheme='Bearer', credentials=result.json()['access_token'])
    assert auth.verify_token(credentials)['sub'] == 'analyst'


def test_weak_signing_key_rejected(monkeypatch):
    monkeypatch.setenv('JWT_SECRET', 'weak')
    with pytest.raises(auth.HTTPException) as error:
        auth.signing_key()
    assert error.value.status_code == 503


@pytest.mark.parametrize('claims', [{'exp': 1}, {'sub': None}])
def test_invalid_claims_rejected(claims):
    response = TestClient(main.app).get('/api/train/status', headers={'Authorization': 'Bearer ' + token(**claims)})
    assert response.status_code == 401


def test_idle_training_does_not_invent_results(monkeypatch):
    cache = MagicMock()
    cache.get.return_value = None
    cache.lrange.return_value = []
    monkeypatch.setattr(main, 'redis_client', cache)
    result = TestClient(main.app).get('/api/train/status', headers=headers()).json()
    assert result['status'] == 'idle'
    assert result['accuracy'] == result['f1_macro'] == result['rows'] == 0
    assert not any(result['dataset_progress'].values())


def test_dependency_outage_visible(monkeypatch):
    cache = MagicMock()
    cache.ping.side_effect = main.redis.ConnectionError('offline')
    cache.get.side_effect = main.redis.ConnectionError('offline')
    monkeypatch.setattr(main, 'redis_client', cache)
    client = TestClient(main.app)
    assert client.get('/health').status_code == 200
    ready = client.get('/ready')
    assert ready.status_code == 503
    assert ready.json()['services'] == {'postgres': False, 'redis': False}
    assert client.get('/api/alerts', headers=headers()).status_code == 503
    assert client.get('/api/train/status', headers=headers()).status_code == 503
    assert client.get('/api/stats', headers=headers()).status_code == 503
    assert client.get('/dashboard/index.html').status_code == 200


def test_websocket_rejects_demo():
    with TestClient(main.app).websocket_connect('/api/ws/alerts') as ws:
        ws.send_json({'token': 'demo'})
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_json()
        assert error.value.code == 1008
    assert not main.manager.active_connections


def test_websocket_authorized_cleanup():
    with TestClient(main.app).websocket_connect('/api/ws/alerts') as ws:
        ws.send_json({'token': token()})
        ws.send_text('heartbeat')
    assert not main.manager.active_connections


@pytest.mark.parametrize('rule,flow,expected', [
    ({'sni_pattern': r'^trusted\.local$'}, {'sni': 'trusted.local'}, True),
    ({'sni_pattern': r'^trusted\.local$'}, {'sni': 'evil.local'}, False),
    ({'sni_pattern': '['}, {'sni': 'anything'}, False),
    ({'sni_pattern': 'trusted'}, {'sni': None}, False),
    ({'src_ip_cidr': 'bad-cidr'}, {'src': '10.0.0.1'}, False),
    ({'src_ip_cidr': '0.0.0.0/0'}, {}, False),
    ({'dst_ip_cidr': '10.0.0.0/8'}, {'dst': '10.1.2.3'}, True),
    ({'dst_port': 443}, {'dport': 80}, False),
    ({'threat_type': 'dns_tunnel'}, {}, False),
])
def test_suppression_conditions(rule, flow, expected):
    db = MagicMock()
    db.get_active_suppression_rules = AsyncMock(return_value=[{'rule_id': 'rule-1', 'name': 'test', **rule}])
    engine = SuppressionEngine(db)
    asyncio.run(engine.reload_rules())
    assert bool(engine.should_suppress(flow, 'c2_beacon')) is expected


def test_mock_execution_never_reported_as_success(monkeypatch):
    monkeypatch.setattr(main.db, 'pool', MagicMock())
    client = TestClient(main.app)
    assert client.patch('/api/response/queue/id/approve', headers=headers()).status_code == 403
    assert client.patch('/api/response/queue/id/approve', headers=headers(['admin'])).status_code == 501


def test_reset_requires_admin(monkeypatch):
    monkeypatch.setattr(main.db, 'pool', MagicMock())
    assert TestClient(main.app).post('/api/alerts/reset', headers=headers()).status_code == 403

def test_rs256_login_and_verification_agree(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    config = {'private_key': private, 'public_key': public}
    monkeypatch.setattr(auth.secrets, 'get_jwt_config', lambda: config)
    monkeypatch.setattr(auth.secrets, 'get_secret', lambda name: config)
    monkeypatch.setenv('ENV', 'dev')
    monkeypatch.setenv('ALLOW_DEV_LOGIN', 'true')
    result = TestClient(main.app).post('/api/auth/login', json={'username': 'tester', 'password': 'dev'})
    assert result.status_code == 200
    assert jwt.get_unverified_header(result.json()['access_token'])['alg'] == 'RS256'
    identity = auth.verify_token(auth.HTTPAuthorizationCredentials(scheme='Bearer', credentials=result.json()['access_token']))
    assert identity['sub'] == 'tester'


def test_training_launch_failure_marks_failed(monkeypatch):
    cache = MagicMock()
    cache.get.return_value = 'idle'
    cache.lock.return_value.acquire.return_value = True
    monkeypatch.setattr(main, 'redis_client', cache)
    launch = MagicMock(side_effect=OSError('cannot spawn'))
    monkeypatch.setattr(main.subprocess, 'Popen', launch)
    result = TestClient(main.app).post('/api/train/run', headers=headers(['admin']))
    assert result.status_code == 503
    cache.set.assert_any_call('train_status', 'failed')
    cache.lock.return_value.release.assert_called_once()


def test_training_launch_contention_does_not_spawn(monkeypatch):
    cache = MagicMock()
    cache.lock.return_value.acquire.return_value = False
    monkeypatch.setattr(main, 'redis_client', cache)
    launch = MagicMock()
    monkeypatch.setattr(main.subprocess, 'Popen', launch)
    result = TestClient(main.app).post('/api/train/run', headers=headers(['admin']))
    assert result.json()['status'] == 'already_running'
    launch.assert_not_called()


def test_ready_probes_both_services(monkeypatch):
    cache = MagicMock()
    cache.ping.return_value = True
    connection = MagicMock()
    connection.fetchval = AsyncMock(return_value=1)
    pool = MagicMock()
    pool.acquire.return_value.__aenter__.return_value = connection
    monkeypatch.setattr(main, 'redis_client', cache)
    monkeypatch.setattr(main.db, 'pool', pool)
    result = TestClient(main.app).get('/ready')
    assert result.status_code == 200
    assert all(result.json()['services'].values())


def test_flow_count_is_not_fabricated(monkeypatch):
    cache = MagicMock()
    cache.get.side_effect = lambda key: '2' if key == 'stats:c2_count' else None
    cache.mget.return_value = [None] * 5
    monkeypatch.setattr(main, 'redis_client', cache)
    result = TestClient(main.app).get('/api/stats', headers=headers()).json()
    assert result['threat_counts']['c2_beacon'] == 2
    assert result['flows_total'] == 0


def test_cidr_normalized():
    from api.routes.suppression import clean_cidr
    assert clean_cidr('10.2.3.4/8') == '10.0.0.0/8'
    assert clean_cidr('::1') == '::1/128'
