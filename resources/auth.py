import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from flask_restful import Resource
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt, decode_token
)
import pyotp
from model import User, TokenBlacklist, db
from .utils import login_parser, store_refresh_token, bcrypt

logger = logging.getLogger(__name__)

class LoginResources(Resource):
    def post(self):
        try:
            args = login_parser.parse_args()
            logger.info(f"Login attempt for username: {args['username']}")
        except Exception as e:
            logger.error(f"Failed to parse login request: {str(e)}")
            return {'error': 'Failed to parse request', 'details': str(e)}, 400
        
        username = args['username']
        password = args['password']
        mfa_code = args.get('mfa_code')

        user = User.query.filter_by(username=username).first()

        # Reject OAuth users
        if user.is_oauth:
            logger.warning(f"OAuth user {username} attempted password login")
            return {'message': 'Please use OAuth to log in'}, 400

        if not user:
            logger.warning(f'User not found: {username}')
            return {'message': 'Invalid Credentials'}, 401

        if not user.is_active:
            logger.info(f"Inactive user login attempt: {username}")
            return {'message': 'Account not activated. Please confirm your email.'}, 403


        # Require OTP for non-OAuth users with an email
        if user.email:
            try:
                from resources.otp import send_otp_to_email
                otp_result, status_code = send_otp_to_email(user.email)
                if status_code == 200:
                    logger.info(f"OTP sent successfully for user: {username}")
                    return {'message': 'OTP sent to your email. Please verify to complete login.', 'requires_otp': True}, 200
                else:
                    logger.error(f'Failed to send OTP for user {username}:{otp_result.get("message", "Unknown error")}')
                    return {'message': 'Failed to send OTP. Please try again.','error': otp_result.get('message', 'Unknown error')}, status_code
            except Exception as e:
                logger.error(f"Failed to send OTP for user {username}: {str(e)}")
                return {'message': 'Failed to send OTP. Please try again.', 'error': str(e)}, 500
        # MFA verification for users with MFA enabled
        if user.mfa_enabled:
            if not mfa_code or not pyotp.TOTP(user.get_mfa_secret()).verify(mfa_code):
                logger.warning(f"Invalid MFA code for user: {username}")
                return {'message': 'Invalid MFA code'}, 401

        # Validate password for non-OAuth users
        if not user.password or not bcrypt.check_password_hash(user.password, password):
            logger.warning(f"Failed login attempt for username: {username}")
            return {'message': 'Invalid credentials'}, 401

        # Update last activity
        user.last_activity = datetime.now(ZoneInfo('Africa/Lagos'))
        db.session.commit()

        # Generate tokens
        access_token = create_access_token(identity=user.token_id, additional_claims={'username': user.username})
        refresh_token = create_refresh_token(identity=user.token_id, additional_claims={'username': user.username})
        
        # Store refresh token in database
        decoded_refresh = decode_token(refresh_token)
        expires_at = datetime.fromtimestamp(decoded_refresh['exp'], ZoneInfo('Africa/Lagos'))
        store_refresh_token(user.id, decoded_refresh['jti'], expires_at)
        
        logger.info(f"Successful login for user: {username}")
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Login Successful'
        }, 200

class LogoutResources(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        db.session.add(TokenBlacklist(jti=jti))
        db.session.commit()
        return {'message': 'Logout Successful'}, 200