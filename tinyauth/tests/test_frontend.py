import json
import os
from unittest import mock

from flask import send_from_directory

from tinyauth.models import WebAuthnCredential, db

from . import base
from .fido2 import Authenticator


class TestInvalidToken(base.TestCase):

    def setUp(self):
        super().setUp()
        self.client.set_cookie('localhost', 'tinysess', 'INVALID-TOKEN')

    def test_login_static(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/login/static/test_frontend.py')
        assert response.status_code == 200

    def test_static_404(self):
        response = self.client.get('/static/404.js')
        assert response.status_code == 404

    def test_static_200(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/static/test_frontend.py')
        assert response.status_code == 404

    def test_index(self):
        response = self.client.get('/')

        assert response.status_code == 302
        assert response.headers['Location'] == 'http://localhost/login'

    def test_login_DEBUG(self):
        self.app.config['DEBUG'] = True

        response = self.client.get('/login')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/login/static/js/bundle.js">' in body
        assert body.endswith('</html>')

    def test_login(self):
        assets = json.dumps({
            'main.js': 'static/js/bundle.c0ff33.js',
        })

        with mock.patch('tinyauth.frontend.open', mock.mock_open(read_data=assets)):
            response = self.client.get('/login')

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/login/static/js/bundle.c0ff33.js">' in body
        assert body.endswith('</html>')


class TestLoggedInUI(base.TestCase):

    def setUp(self):
        super().setUp()

        response = self.client.post(
            '/login',
            data=json.dumps({
                'username': 'charles',
                'password': 'mrfluffy',
            }),
            content_type='application/json',
        )
        assert response.status_code == 200

        assert {} == json.loads(response.get_data(as_text=True))

    def test_login_static(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/login/static/test_frontend.py')
        assert response.status_code == 200

    def test_static_404(self):
        response = self.client.get('/static/404.js')
        assert response.status_code == 404

    def test_static_200(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/static/test_frontend.py')
        assert response.status_code == 200

    def test_index_DEBUG(self):
        self.app.config['DEBUG'] = True
        response = self.client.get('/')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/static/js/bundle.js">' in body
        assert body.endswith('</html>')

    def test_index(self):
        assets = json.dumps({
            'main.js': 'static/js/bundle.c0ff33.js',
            'main.css': 'static/css/main.c0ff33.css',
        })

        with mock.patch('tinyauth.frontend.open', mock.mock_open(read_data=assets)):
            response = self.client.get('/')

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/static/js/bundle.c0ff33.js">' in body
        assert '<link href="/static/css/main.c0ff33.css" rel="stylesheet">' in body
        assert body.endswith('</html>')

    def test_login(self):
        response = self.client.get('/login')
        assert response.status_code == 302
        assert response.headers['Location'] == 'http://localhost/'

    def test_logout(self):
        assert len(self.client.cookie_jar._cookies['localhost.local']['/']) == 2

        response = self.client.get('/logout')
        assert response.status_code == 302
        assert response.headers['Location'] == 'http://localhost/login'

        assert len(self.client.cookie_jar._cookies['localhost.local']['/']) == 0

    def test_use_api_with_token(self):
        response = self.client.get(
            '/api/v1/users',
            headers={
                'X-CSRF-Token': self.client.cookie_jar._cookies['localhost.local']['/']['tinycsrf'].value,
            }
        )

        assert response.status_code == 200
        assert json.loads(response.get_data(as_text=True)) == [{
            'groups': [],
            'id': 'charles',
            'username': 'charles',
        }, {
            'groups': [],
            'id': 'freddy',
            'username': 'freddy',
        }]


class TestLoggedOutUI(base.TestCase):

    def test_login_static(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/login/static/test_frontend.py')
        assert response.status_code == 200

    def test_static_404(self):
        response = self.client.get('/static/404.js')
        assert response.status_code == 404

    def test_static_200(self):
        def send_from_test(directory, filename, **options):
            return send_from_directory(
                os.path.dirname(__file__),
                filename,
                **options,
            )
        self.patch('tinyauth.frontend.send_from_directory', new=send_from_test)
        response = self.client.get('/static/test_frontend.py')
        assert response.status_code == 404

    def test_index(self):
        response = self.client.get('/')

        assert response.status_code == 302
        assert response.headers['Location'] == 'http://localhost/login'

    def test_login_DEBUG(self):
        self.app.config['DEBUG'] = True

        response = self.client.get('/login')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/login/static/js/bundle.js">' in body
        assert body.endswith('</html>')

    def test_login(self):
        assets = json.dumps({
            'main.js': 'static/js/bundle.c0ff33.js',
        })

        with mock.patch('tinyauth.frontend.open', mock.mock_open(read_data=assets)):
            response = self.client.get('/login')

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/html; charset=utf-8'

        body = response.get_data(as_text=True).strip()
        assert '<script type="text/javascript" src="/login/static/js/bundle.c0ff33.js">' in body
        assert body.endswith('</html>')


class TestWebAuthn(base.TestCase):

    def test_mfa_dance(self):
        a = Authenticator()

        db.session.add(WebAuthnCredential(
            user=self.user,
            credential_id=a.credential_id,
            public_key=a.serialized_public_key,
            sign_count=0,
        ))
        db.session.commit()

        response = self.client.post(
            '/login',
            data=json.dumps({
                'username': 'charles',
                'password': 'mrfluffy',
            }),
            content_type='application/json',
        )
        assert response.status_code == 200

        challenge = json.loads(response.get_data(as_text=True))
        assert challenge['mfa-required'] is True
        assert challenge['authenticators'] == [a.credential_id]

        attestation = a.get(challenge=challenge)

        response = self.client.post(
            '/login',
            data=json.dumps({
                'username': 'charles',
                'password': 'mrfluffy',
                'credentialId': a.credential_id,
                'authenticatorData': list(bytearray(attestation['attestation'])),
                'clientData': list(bytearray(attestation['client-data'])),
                'signature': list(bytearray(attestation['signature'])),
            }),
            content_type='application/json',
        )
        assert response.status_code == 200

        assert {} == json.loads(response.get_data(as_text=True))
