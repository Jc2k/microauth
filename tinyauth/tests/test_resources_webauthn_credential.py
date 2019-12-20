import json

from tinyauth.models import WebAuthnCredential, db

from . import base
from .fido2 import Authenticator


class TestCase(base.TestCase):

    def test_add_webauthn_credential(self):
        a = Authenticator()

        response = self.req('get', '/api/v1/users/charles/webauthn-credentials')
        assert response.status_code == 200
        assert json.loads(response.get_data(as_text=True)) == []

        response = self.req('post', '/api/v1/users/charles/webauthn-credentials')
        assert response.status_code == 200
        data = json.loads(response.get_data(as_text=True))

        created = a.create(challenge=data['challenge'])

        response = self.req('post', '/api/v1/users/charles/webauthn-credentials/complete', body={
            'name': 'asdasdasdasdasd',
            'publickey': {
                'clientData': list(bytearray(created['client-data'])),
                'attObj': list(bytearray(created['attestation'])),
            },
        })

        assert response.status_code == 200
        completion = json.loads(response.get_data(as_text=True))

        assert completion == {
            'credential_id': 'ZGZkZmRmZGZkZg==',
            'id': '1',
            'name': 'asdasdasdasdasd',
            'sign_count': 0,
        }

    def test_list_user_credentials(self):
        db.session.add(WebAuthnCredential(
            user=self.user,
            name='yubikey-1',
            credential_id='zzzzzz',
            sign_count=0,
        ))
        db.session.commit()

        response = self.req('get', '/api/v1/users/charles/webauthn-credentials')

        assert response.status_code == 200
        assert json.loads(response.get_data(as_text=True)) == [{
            'id': '1',
            'name': 'yubikey-1',
            'sign_count': 0,
            'credential_id': 'zzzzzz',
        }]

        args, kwargs = self.audit_log.call_args_list[0]
        assert args[0] == 'ListWebAuthCredentials'
        assert kwargs['extra'] == {
            'request-id': 'a823a206-95a0-4666-b464-93b9f0606d7b',
            'http.status': 200,
            'request.username': 'charles',
        }

    def test_get_user_credential(self):
        db.session.add(WebAuthnCredential(
            user=self.user,
            name='yubikey-1',
            credential_id='zzzzzz',
            sign_count=0,
        ))
        db.session.commit()

        response = self.req('get', '/api/v1/users/charles/webauthn-credentials/1')

        assert response.status_code == 200
        assert json.loads(response.get_data(as_text=True)) == {
            'id': '1',
            'name': 'yubikey-1',
            'sign_count': 0,
            'credential_id': 'zzzzzz',
        }

        args, kwargs = self.audit_log.call_args_list[0]
        assert args[0] == 'GetWebAuthnCredential'
        assert kwargs['extra'] == {
            'request-id': 'a823a206-95a0-4666-b464-93b9f0606d7b',
            'http.status': 200,
            'request.username': 'charles',
            'request.credential': '1',
        }

    def test_delete_user_credential(self):
        db.session.add(WebAuthnCredential(
            user=self.user,
            name='yubikey-1',
            credential_id='zzzzzz',
            sign_count=0,
        ))
        db.session.commit()

        response = self.req('delete', '/api/v1/users/charles/webauthn-credentials/1')

        assert response.status_code == 201
        assert json.loads(response.get_data(as_text=True)) == {}

        response = self.req('get', '/api/v1/users/charles/webauthn-credentials')
        assert len(json.loads(response.get_data(as_text=True))) == 0

        args, kwargs = self.audit_log.call_args_list[0]
        assert args[0] == 'DeleteWebAuthnCredential'
        assert kwargs['extra'] == {
            'request-id': 'a823a206-95a0-4666-b464-93b9f0606d7b',
            'http.status': 201,
            'request.username': 'charles',
            'request.credential': '1',
        }
