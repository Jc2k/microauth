import collections
import datetime
import itertools
import json
import logging
import uuid

import jwt
from flask import Blueprint, current_app, jsonify
from werkzeug.datastructures import Headers

from ..audit import audit_request, format_headers_for_audit_log
from ..authorize import (
    external_authorize,
    external_authorize_login,
    format_arn,
    get_arn_base,
    internal_authorize,
)
from ..exceptions import AuthenticationError
from ..models import User
from ..reqparse import RequestParser

service_blueprint = Blueprint('service', __name__)

authorize_parser = RequestParser()
authorize_parser.add_argument('action', type=str, location='json', required=True)
authorize_parser.add_argument('resource', type=str, location='json', required=True)
authorize_parser.add_argument('headers', type=list, location='json', required=True)
authorize_parser.add_argument('context', type=dict, location='json', required=True)

batch_authorize_parser = RequestParser()
batch_authorize_parser.add_argument('permit', type=dict, location='json', required=True)
batch_authorize_parser.add_argument('headers', type=list, location='json', required=True)
batch_authorize_parser.add_argument('context', type=dict, location='json', required=True)

logger = logging.getLogger("tinyauth.audit")


@service_blueprint.route('/api/v1/authorize-login', methods=['POST'])
@audit_request('AuthorizeByLogin')
def service_authorize_login(audit_ctx):
    internal_authorize('Authorize', get_arn_base())

    args = authorize_parser.parse_args()

    audit_ctx['request.actions'] = [args['action']]
    audit_ctx['request.resources'] = [args['resource']]
    audit_ctx['request.permit'] = json.dumps({args['action']: [args['resource']]}, indent=4, separators=(',', ': '))
    audit_ctx['request.headers'] = format_headers_for_audit_log(args['headers'])
    audit_ctx['request.context'] = args['context']

    result = external_authorize_login(
        action=args['action'],
        resource=args['resource'],
        headers=Headers(args['headers']),
        context=args['context'],
    )

    audit_ctx['response.authorized'] = result['Authorized']
    if 'Identity' in result:
        audit_ctx['response.identity'] = result['Identity']

    return jsonify(result)


@service_blueprint.route('/api/v1/authorize', methods=['POST'])
@audit_request('AuthorizeByToken')
def service_authorize(audit_ctx):
    audit_ctx['request.legacy'] = True

    internal_authorize('Authorize', get_arn_base())

    args = authorize_parser.parse_args()

    audit_ctx['request.actions'] = [args['action']]
    audit_ctx['request.resources'] = [args['resource']]
    audit_ctx['request.permit'] = json.dumps({args['action']: [args['resource']]}, indent=4, separators=(',', ': '))
    audit_ctx['request.headers'] = format_headers_for_audit_log(args['headers'])
    audit_ctx['request.context'] = args['context']

    result = external_authorize(
        action=args['action'],
        resource=args['resource'],
        headers=Headers(args['headers']),
        context=args['context'],
    )

    audit_ctx['response.authorized'] = result['Authorized']
    if 'Identity' in result:
        audit_ctx['response.identity'] = result['Identity']

    return jsonify(result)


@service_blueprint.route('/api/v1/services/<service>/get-token-for-login', methods=['POST'])
@audit_request('GetTokenForLogin')
def get_token_for_login(audit_ctx, service):
    audit_ctx['request.service'] = service
    internal_authorize('GetTokenForLogin', format_arn('services', service))

    user_parser = RequestParser()
    user_parser.add_argument('username', type=str, location='json', required=True)
    user_parser.add_argument('password', type=str, location='json', required=True)
    user_parser.add_argument('csrf-strategy', type=str, location='json', required=True)
    req = user_parser.parse_args()

    audit_ctx['request.username'] = req['username']
    audit_ctx['request.csrf-strategy'] = req['csrf-strategy']

    errors = {
        'authentication': 'Invalid credentials',
    }
    response = jsonify(errors=errors)
    response.status_code = 401

    if req['csrf-strategy'] not in ('header-token', 'cookie', 'none'):
        raise AuthenticationError(description=errors, response=response)

    user = User.query.filter(User.username == req['username']).first()
    if not user or not user.password:
        raise AuthenticationError(description=errors, response=response)

    if not user.is_valid_password(req['password']):
        raise AuthenticationError(description=errors, response=response)

    expires = datetime.datetime.utcnow() + datetime.timedelta(hours=8)

    token_contents = {
        'user': user.id,
        'mfa': False,
        'exp': expires,
        'iat': datetime.datetime.utcnow(),
    }

    if req['csrf-strategy'] == 'header-token':
        token_contents['csrf-token'] = str(uuid.uuid4())

    jwt_token = jwt.encode(
        token_contents,
        current_app.config['SECRET_SIGNING_KEY'],
        algorithm='HS256',
    )

    response = {'token': jwt_token.decode('utf-8')}
    if 'csrf-token' in token_contents:
        response['csrf'] = token_contents['csrf-token']

    return jsonify(response)


@service_blueprint.route('/api/v1/services/<service>/authorize-by-token', methods=['POST'])
@audit_request('AuthorizeByToken')
def batch_service_authorize(audit_ctx, service):
    audit_ctx['request.service'] = service
    audit_ctx['response.authorized'] = False

    internal_authorize('BatchAuthorizeByToken', format_arn('services', service))

    args = batch_authorize_parser.parse_args()

    audit_ctx.update({
        'request.actions': args['permit'].keys(),
        'request.resources': list(itertools.chain(*args['permit'].values())),
        'request.permit': json.dumps(args['permit'], indent=4, separators=(',', ': ')),
        'request.headers': format_headers_for_audit_log(args['headers']),
        'request.context': args['context'],
    })

    result = {
       'Permitted': collections.defaultdict(list),
       'NotPermitted': collections.defaultdict(list),
       'Authorized': False,
    }

    # FIXME: Refactor this to only need to verify identity once and reuse the extracted policies for multiple verifications
    for action, resources in args['permit'].items():
        for resource in resources:
            step_result = external_authorize(
                action=':'.join((service, action)),
                resource=resource,
                headers=Headers(args['headers']),
                context=args['context'],
            )

            grant_set = result['Permitted' if step_result['Authorized'] else 'NotPermitted']
            grant_set[action].append(resource)

            if not step_result['Authorized']:
                result['ErrorCode'] = step_result['ErrorCode']

    audit_ctx['response.permitted'] = json.dumps(dict(result['Permitted']), indent=4, separators=(',', ': '))
    audit_ctx['response.not-permitted'] = json.dumps(dict(result['NotPermitted']), indent=4, separators=(',', ': '))

    if len(result['NotPermitted']) == 0 and len(result['Permitted']) > 0:
        audit_ctx['response.authorized'] = result['Authorized'] = True
        audit_ctx['response.identity'] = result['Identity'] = step_result['Identity']

    return jsonify(result)
