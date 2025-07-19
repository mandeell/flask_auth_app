import logging
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
import pyotp

from model import User, db
from .utils import mfa_parser

logger = logging.getLogger(__name__)

class MFASetupResources(Resource):
    @jwt_required()
    def post(self):
        logger.info("Reached /mfa POST endpoint")
        user_id = get_jwt_identity()
        logger.info(f"JWT Identity: {user_id}")
        user = User.query.filter_by(token_id=user_id).first()
        logger.info(f"Found user: {user.username}")
        
        if not user.mfa_secret:
            # Generate new secret and encrypt it
            secret = pyotp.random_base32()
            user.set_mfa_secret(secret)
            db.session.commit()
        
        # Get the decrypted secret for QR code generation
        secret = user.get_mfa_secret()
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            user.email, 
            issuer_name='MyApp'
        )
        
        return {
            'mfa_secret': secret,  # Return the secret for manual entry
            'provisioning_uri': provisioning_uri,  # Return URI for QR code generation
            'qr_code_url': f'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={provisioning_uri}'
        }, 200

    @jwt_required()
    def put(self):
        args = mfa_parser.parse_args()
        user_id = get_jwt_identity()
        user = User.query.filter_by(token_id=user_id).first()

        # Get the decrypted secret for verification
        secret = user.get_mfa_secret()
        if secret and pyotp.TOTP(secret).verify(args['mfa_code']):
            user.mfa_enabled = True
            db.session.commit()
            return {'message': 'MFA Enabled'}, 200
        return {'message': 'Invalid MFA code'}, 401