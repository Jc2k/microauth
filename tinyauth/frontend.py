import datetime
import json
import uuid
from urllib.parse import urljoin, urlparse

import jwt
from flask import (
    Blueprint,
    Response,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
)

from tinyauth.models import User

frontend_blueprint = Blueprint('frontend', __name__, static_folder=None)


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def get_session():
    session = request.cookies.get('tinysess')
    if not session:
        return None

    try:
        token = jwt.decode(session, 'secret')
    except jwt.InvalidTokenError:
        return None

    return token


@frontend_blueprint.route('/login')
def login():
    auth = request.authorization

    if not auth:
        return Response('', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    user = User.query.filter(User.username == auth.username).first()
    if not user or not user.password:
        return Response('', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    if not user.is_valid_password(auth.password):
        return Response('', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    expires = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    csrf_token = str(uuid.uuid4())

    jwt_token = jwt.encode({
        'user': user.id,
        'mfa': False,
        'exp': expires,
        'iat': datetime.datetime.utcnow(),
        'csrf-token': csrf_token,
    }, 'secret', algorithm='HS256')

    response = redirect('/')
    response.set_cookie('tinysess', jwt_token, httponly=True, secure=True, expires=expires)
    response.set_cookie('tinycsrf', csrf_token, httponly=False, secure=True, expires=expires)

    return response


@frontend_blueprint.route('/static/<path:path>')
def static(path):
    session = get_session()
    if not session:
        abort(404)

    return send_from_directory(
        '/app/react/static',
        path,
    )


@frontend_blueprint.route('/')
def index():
    session = get_session()
    if not session:
        return redirect('/login')

    with open('/app/react/asset-manifest.json', 'r') as fp:
        assets = json.loads(fp.read())

    return render_template(
       'frontend/index.html',
       css_hash=assets['main.css'],
       js_hash=assets['main.js'],
      )