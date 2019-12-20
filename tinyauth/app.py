#! /usr/bin/env python3

import logging
import os
import secrets

import click
from flask import Flask
from flask.cli import FlaskGroup
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.contrib.fixers import ProxyFix

from .audit import setup_audit_log
from .middleware import RequestIdMiddleware

logger = logging.getLogger('tinyauth.app')

db = SQLAlchemy()


def configure_backend_db(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if 'SECRET_SIGNING_KEY' not in os.environ:
        logger.critical('*** DANGER: SECRET_SIGNING_KEY not set; using random default ***')
        app.config['SECRET_SIGNING_KEY'] = secrets.token_hex(64)
    else:
        app.config['SECRET_SIGNING_KEY'] = os.environ['SECRET_SIGNING_KEY']

    db.init_app(app)
    Migrate(app, db)

    from . import resources
    app.register_blueprint(resources.user_blueprint)
    app.register_blueprint(resources.access_key_blueprint)
    app.register_blueprint(resources.user_policy_blueprint)
    app.register_blueprint(resources.group_blueprint)
    app.register_blueprint(resources.group_policy_blueprint)
    app.register_blueprint(resources.service_blueprint)
    app.register_blueprint(resources.webauthn_credential_blueprint)

    from . import frontend
    app.register_blueprint(frontend.frontend_blueprint)

    from .backends.db import Backend
    app.auth_backend = Backend()


def configure_backend_proxy(app):
    app.config['TINYAUTH_ENDPOINT'] = os.environ['TINYAUTH_ENDPOINT']
    app.config['TINYAUTH_ACCESS_KEY_ID'] = os.environ['TINYAUTH_ACCESS_KEY_ID']
    app.config['TINYAUTH_SECRET_ACCESS_KEY'] = os.environ['TINYAUTH_SECRET_ACCESS_KEY']
    app.config['TINYAUTH_VERIFY'] = os.environ.get('TINYAUTH_VERIFY', 'true').lower() in ('true', 'yes')

    from . import resources
    app.register_blueprint(resources.service_blueprint)

    from .backends import proxy
    app.auth_backend = proxy.Backend()


def create_app(info):
    app = Flask(
        __name__,
        static_folder=None,
    )

    app.config['TINYAUTH_PARTITION'] = os.environ.get('TINYAUTH_PARTITION', 'tinyauth')
    app.config['TINYAUTH_SERVICE'] = os.environ.get('TINYAUTH_SERVICE', 'tinyauth')

    app.wsgi_app = ProxyFix(app.wsgi_app)
    RequestIdMiddleware(app)

    app.config['AUDIT_LOG_FILENAME'] = os.environ.get('AUDIT_LOG_FILENAME', None)
    setup_audit_log(app)

    CORS(app, resources={r'/api/*': {'origins': '*', 'expose_headers': 'Content-Range'}})

    app.config['TINYAUTH_AUTH_MODE'] = os.environ.get('TINYAUTH_AUTH_MODE', 'db')
    if app.config.get('TINYAUTH_AUTH_MODE', 'db') == 'db':
        configure_backend_db(app)
    elif app.config['TINYAUTH_AUTH_MODE'] == 'proxy':
        configure_backend_proxy(app)

    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a management script for the wiki application."""


@cli.command()
def createdevuser():
    from .models import AccessKey, User, UserPolicy, db
    p = UserPolicy(name='root', policy={'Statement': [{'Action': '*', 'Resource': '*', 'Effect': 'Allow'}]})
    db.session.add(p)

    u = User(username='root')
    u.set_password('password')
    u.policies.append(p)
    db.session.add(u)

    k = AccessKey(access_key_id='gatekeeper', secret_access_key='keymaster', user=u)
    db.session.add(k)

    db.session.commit()

    click.echo("'root' account created")
