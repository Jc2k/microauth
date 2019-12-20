import base64
import json
from hmac import compare_digest

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject
from fido2.rpid import verify_app_id
from fido2.utils import sha256
from flask import Blueprint, jsonify, make_response, request
from flask_restful import Api, Resource, abort, fields, marshal, reqparse

from tinyauth.app import db
from tinyauth.audit import audit_request, audit_request_cbv
from tinyauth.authorize import format_arn, internal_authorize
from tinyauth.models import User, WebAuthnCredential
from tinyauth.simplerest import build_response_for_request


class Json(fields.Raw):
    def format(self, value):
        return json.dumps(value)


webauthn_credential_fields = {
    'id': fields.String(attribute='id'),
    'name': fields.String,
    'credential_id': fields.String,
    'sign_count': fields.Integer,
}

webauthn_credential_parser = reqparse.RequestParser()
webauthn_credential_parser.add_argument('name', type=str, location='json', required=True)

webauthn_credential_blueprint = Blueprint('webauthn_credential', __name__)


class WebAuthnCredentialResource(Resource):

    def _get_or_404(self, user, credential_id):
        credential = WebAuthnCredential.query.filter_by(user=user, id=credential_id).first()
        if not credential:
            abort(404, message=f'Policy {credential_id} for user {user} does not exist')
        return credential

    @audit_request_cbv('GetWebAuthnCredential')
    def get(self, audit_ctx, username, credential_id):
        audit_ctx['request.username'] = username
        audit_ctx['request.credential'] = credential_id
        internal_authorize('GetWebAuthnCredential', format_arn('users', username))

        user = User.query.filter(User.username == username).first()
        if not user:
            abort(404, message=f'User doesn\'t exist')

        credential = self._get_or_404(user, credential_id)
        return jsonify(marshal(credential, webauthn_credential_fields))

    @audit_request_cbv('UpdateWebAuthnCredential')
    def put(self, audit_ctx, username, credential_id):
        audit_ctx['request.username'] = username
        audit_ctx['request.credential'] = credential_id
        internal_authorize('UpdateWebAuthnCredential', format_arn('users', username))

        user = User.query.filter(User.username == username).first()
        if not user:
            abort(404, message=f'User doesn\'t exist')

        args = webauthn_credential_parser.parse_args()
        audit_ctx['request.new-name'] = args['name']

        credential = self._get_or_404(user, credential_id)
        credential.name = args['name']
        db.session.add(credential)

        db.session.commit()

        return jsonify(marshal(credential, webauthn_credential_fields))

    @audit_request_cbv('DeleteWebAuthnCredential')
    def delete(self, audit_ctx, username, credential_id):
        audit_ctx['request.username'] = username
        audit_ctx['request.credential'] = credential_id
        internal_authorize('DeleteWebAuthnCredential', format_arn('users', username))

        user = User.query.filter(User.username == username).first()
        if not user:
            abort(404, message=f'User doesn\'t exist')

        credential = self._get_or_404(user, credential_id)
        db.session.delete(credential)
        db.session.commit()

        return make_response(jsonify({}), 201, [])


class WebAuthCredentialsResource(Resource):

    @audit_request_cbv('ListWebAuthCredentials')
    def get(self, audit_ctx, username):
        audit_ctx['request.username'] = username
        internal_authorize('ListWebAuthCredentials', format_arn('users', username))

        user = User.query.filter(User.username == username).first()
        if not user:
            abort(404, message=f'User doesn\'t exist')

        return build_response_for_request(
            WebAuthnCredential,
            request,
            webauthn_credential_fields,
            WebAuthnCredential.query.filter(WebAuthnCredential.user == user),
        )

    @audit_request_cbv('CreateWebAuthnCredential')
    def post(self, audit_ctx, username):
        audit_ctx['request.username'] = username
        internal_authorize('CreateWebAuthnCredential', format_arn('users', username))

        # args = webauthn_credential_parser.parse_args()

        user = User.query.filter(User.username == username).first()
        if not user:
            abort(404, message=f'User doesn\'t exist')

        return jsonify({
            'rp': {
                'id': 'localhost',
                'name': 'Tinyauth',
            },
            'user': {
                'id': username,
                'name': username,
                'displayName': username,
            },
            'challenge': 'XXXXXXXXXXX',
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},
            ],
            'excludeCredentials': [],
            'timeout': int(60 * 1000),
            'attestation': 'direct',
        })


@webauthn_credential_blueprint.route('/api/v1/users/<username>/webauthn-credentials/complete', methods=['POST'])
@audit_request('CreateWebAuthnCredentialComplete')
def register_complete(audit_ctx, username):
    internal_authorize('UserRegisterFido', format_arn('users', username))

    user = User.query.filter(User.username == username).first()
    if not user:
        abort(404, message=f'user {username} does not exist')

    json_data = request.get_json()
    name = json_data['name']
    registration_response = json_data['publickey']
    client_data = ClientData(bytes(bytearray(registration_response['clientData'])))
    att_obj = AttestationObject(bytes(bytearray(registration_response['attObj'])))

    if client_data.get('type') != 'webauthn.create':
        raise ValueError('Incorrect type in ClientData.')

    if not verify_app_id(client_data.get('origin'), 'https://localhost'):
        raise ValueError('Invalid origin in client data')

    # if not compare_digest(b'XXXXXXXXXXX', base64.b64decode(client_data['challenge'])):
    #    raise ValueError('Wrong challenge in response.')

    if not compare_digest(sha256('localhost'.encode()), att_obj.auth_data.rp_id_hash):
        raise ValueError('Wrong RP ID hash in response.')

    # TODO: Ensure that we're using an acceptable attestation format.
    att_obj.verify(client_data.hash)

    credential_id = base64.b64encode(att_obj.auth_data.credential_data.credential_id).decode('utf-8')

    existing = WebAuthnCredential.query.filter_by(
        user=user,
        credential_id=credential_id,
    )

    if existing.count() > 0:
        return jsonify({'fail': 'Credential ID already exists'})

    credential = WebAuthnCredential(
        user=user,
        name=name,
        credential_id=credential_id,
        public_key=cbor.dumps(att_obj.auth_data.credential_data.public_key),
        sign_count=att_obj.auth_data.counter,
    )

    db.session.add(credential)
    db.session.commit()

    return jsonify(marshal(credential, webauthn_credential_fields))


webauthn_credential_api = Api(webauthn_credential_blueprint, prefix='/api/v1')
webauthn_credential_api.add_resource(WebAuthCredentialsResource, '/users/<username>/webauthn-credentials')
webauthn_credential_api.add_resource(WebAuthnCredentialResource, '/users/<username>/webauthn-credentials/<credential_id>')
