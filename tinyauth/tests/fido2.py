import base64
import datetime
import json
import struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2 import cbor, cose
from fido2.ctap2 import args
from fido2.utils import sha256

be = default_backend()


class Authenticator(object):

    raw_credential_id = b'dfdfdfdfdf'
    credential_id = base64.b64encode(raw_credential_id).decode()

    def __init__(self):
        self.private_key = ec.generate_private_key(
            ec.SECP256R1(),
            be,
        )

        self.public_key = cose.ES256.from_cryptography_key(
            self.private_key.public_key(),
        )

        self.serialized_public_key = cbor.dumps(self.public_key)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'fido2'),
        ])

        self.cert = x509.CertificateBuilder().\
            subject_name(subject).\
            issuer_name(subject).\
            public_key(self.private_key.public_key()).\
            serial_number(x509.random_serial_number()).\
            not_valid_before(datetime.datetime.utcnow()).\
            not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).\
            sign(self.private_key, hashes.SHA256(), be)

        self.serialized_cert = self.cert.public_bytes(serialization.Encoding.DER)

    def create(self, **kwargs):
        '''
        {
            'attestation': 'direct',
            'challenge': 'XXXXXXXXXXX',
            'excludeCredentials': [],
            'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
            'rp': {'id': 'localhost', 'name': 'Tinyauth'},
            'timeout': 60000,
            'user': {'displayName': 'charles', 'id': 'charles', 'name': 'charles'}
        }
        '''

        client_data = json.dumps({
            'challenge': 'WFhYWFhYWFhYWFg',
            'clientExtensions': {},
            'hashAlgorithm': 'SHA-256',
            'origin': 'https://localhost',
            'type': 'webauthn.create'
        }).encode('utf-8')

        # Fake Attested Credential Data
        aaguid = b'\x00' * 16
        credential_id = self.raw_credential_id
        attested_cred_data = aaguid + struct.pack('>H', len(credential_id)) + credential_id + self.serialized_public_key

        # Fake Authenticator Data
        rp_id_hash = bytes(bytearray.fromhex('49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'))
        extensions = b''
        auth_data = rp_id_hash + struct.pack('>BI', 0x41, 0) + attested_cred_data + extensions

        m = b'\0' + rp_id_hash + sha256(client_data) + credential_id + b'\x04' + self.public_key[-2] + self.public_key[-3]

        statement = {
            'x5c': [self.serialized_cert],
            'sig': self.private_key.sign(m, ec.ECDSA(hashes.SHA256())),
        }

        return {
            'client-data': client_data,
            'attestation': cbor.dumps(args(
                'fido-u2f',
                auth_data,
                statement,
            ))
        }

    def get(self, **kwargs):
        client_data = json.dumps({
            'challenge': 'enh6eHp4enh6eA',
            'clientExtensions': {},
            'hashAlgorithm': 'SHA-256',
            'origin': 'https://localhost',
            'type': 'webauthn.get',
        }).encode()

        # Fake Authenticator Data
        rp_id_hash = bytes(bytearray.fromhex('49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763'))
        auth_data = rp_id_hash + struct.pack('>BI', 0x01, 0)

        m = auth_data + sha256(client_data)
        signature = self.private_key.sign(m, ec.ECDSA(hashes.SHA256()))

        return {
            'client-data': client_data,
            'attestation': auth_data,
            'signature': signature,
        }
