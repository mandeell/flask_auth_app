import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token
import pyotp

from model import User, OTP, db
from .utils import (
    send_otp_parser, verify_otp_parser, generate_otp, 
    send_email_otp, store_refresh_token, bcrypt
)

logger = logging.getLogger(__name__)

def send_otp_to_email(email):
    """Helper function to send OTP to a specific email address"""
    try:
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            return False, 'User not found'
        
        # Check for existing unexpired OTP to prevent flood
        current_time = datetime.now(ZoneInfo('Africa/Lagos')).replace(tzinfo=None)
        existing_otp = OTP.query.filter_by(
            email=email,
            is_verified=False
        ).filter(OTP.expires_at > current_time).first()
        
        if existing_otp:
            return {'message': 'OTP already sent. Please wait before requesting a new one.'}, 429
        
        # Generate OTP
        otp_code = generate_otp()
        
        # Set expiration time (10 minutes from now)
        expires_at = datetime.now(ZoneInfo('Africa/Lagos')).replace(tzinfo=None) + timedelta(minutes=10)
        
        # Delete any existing OTPs for this email
        OTP.query.filter_by(email=email).delete()
        
        # Store OTP in database
        otp_record = OTP(
            email=email,
            otp_code=otp_code,
            expires_at=expires_at,
            user_id=user.id
        )
        db.session.add(otp_record)
        db.session.commit()
        
        # Send email OTP
        if send_email_otp(email, otp_code):
            return {'message': 'OTP sent successfully to your email'}, 200
        else:
            return {'message': 'Failed to send OTP'}, 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error sending OTP: {str(e)}')
        return {'message': 'OTP service error'}, 500

class SendOTPResource(Resource):
    def post(self):
        try:
            args = send_otp_parser.parse_args()
            email = args['email']
            
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            if not user:
                return {'message': 'User not found'}, 404
            
            # Check for existing unexpired OTP to prevent flood
            current_time = datetime.now(ZoneInfo('Africa/Lagos'))
            existing_otp = OTP.query.filter_by(
                email=email,
                is_verified=False
            ).filter(OTP.expires_at > current_time).first()
            
            if existing_otp:
                return {'message': 'OTP already sent. Please wait before requesting a new one.'}, 429
            
            # Generate OTP
            otp_code = generate_otp()
            
            # Set expiration time (10 minutes from now)
            expires_at = datetime.now(ZoneInfo('Africa/Lagos')) + timedelta(minutes=10)
            
            # Delete any existing OTPs for this email
            OTP.query.filter_by(email=email).delete()
            
            # Store OTP in database
            otp_record = OTP(
                email=email,
                otp_code=otp_code,
                expires_at=expires_at,
                user_id=user.id
            )
            db.session.add(otp_record)
            db.session.commit()
            
            # Send email OTP
            if send_email_otp(email, otp_code):
                return {'message': 'OTP sent successfully to your email'}, 200
            else:
                return {'message': 'Failed to send OTP'}, 500
                
        except Exception as e:
            db.session.rollback()
            logger.error(f'Error sending OTP: {str(e)}')
            return {'message': 'OTP service error'}, 500

class VerifyOTPResource(Resource):
    def post(self):
        try:
            args = verify_otp_parser.parse_args()
            email = args['email']
            otp_code = args['otp_code']
            username = args['username']
            password = args['password']
            mfa_code = args.get('mfa_code')

            logger.info(f"Received request: username={username}, email={email}, otp_code={otp_code}")
            
            # Verify user credentials first
            user = User.query.filter_by(username=username).first()
            if not user:
                logger.warning(f"User not found: {username}")
                return {'message': 'Invalid Username or Password'}, 401
            if not user.password or not bcrypt.check_password_hash(user.password, password):
                logger.warning(f"Password incorrect for user: {username}")
                return {'message': 'Invalid Username or Password'}, 401
            if not user.is_active:
                logger.info(f"User inactive: {username}")
                return {'message': 'Account not activated. Please confirm your email.'}, 403

            logger.info(f"User credentials verified for {username}")
            
            # Verify email matches user
            if user.email.lower() != email.lower():
                logger.warning(f"Email mismatch: provided={email}, expected={user.email}")
                return {'message': 'Email does not match user account'}, 400
            
            # Find valid OTP
            otp_record = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                is_verified=False
            ).first()
            
            if not otp_record:
                logger.warning(f"No unverified OTP found for email={email}, otp_code={otp_code}")
                return {'message': 'Invalid OTP code'}, 401
            logger.info(f"OTP record found for {email}")

            # Check if OTP is expired
            current_time = datetime.now(ZoneInfo('Africa/Lagos')).replace(tzinfo=None)
            if current_time > otp_record.expires_at:
                logger.warning(f"OTP expired: expires_at={otp_record.expires_at}, now={current_time}")
                return {'message': 'OTP has expired'}, 401
            logger.info(f"OTP is valid and not expired")
            
            # Mark OTP as verified
            otp_record.is_verified = True
            logger.info(f"OTP marked as verified")
            
            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_code:
                    logger.warning(f"MFA enabled but no code provided for {username}")
                    return {'message': 'MFA code required'}, 401
                secret = user.get_mfa_secret()
                if not secret:
                    logger.error(f'No MFA secret found for user: {username}')
                    return {'message': 'MFA setup incomplete. Please setup MFA.'}, 400
                try:
                    if not pyotp.TOTP(secret).verify(mfa_code):
                        logger.error(f'Invalid MFA code for user: {username}')
                        return {'message': 'Invalid MFA code'}, 401
                except Exception as e:
                    logger.error(f'MFA verification failed for user: {username}: {str(e)}')
                    return {'message': 'Invalid MFA code format'}, 400
                logger.info(f"MFA check passed or not required")
            
            # Update last activity
            user.last_activity = datetime.now(ZoneInfo('Africa/Lagos'))
            logger.info(f"Updated last activity")
            
            # Create tokens
            access_token = create_access_token(identity=user.token_id, additional_claims={'username': user.username})
            refresh_token = create_refresh_token(identity=user.token_id, additional_claims={'username': user.username})
            
            # Store refresh token in database
            decoded_refresh = decode_token(refresh_token)
            expires_at = datetime.fromtimestamp(decoded_refresh['exp'], ZoneInfo('Africa/Lagos'))
            store_refresh_token(user.id, decoded_refresh['jti'], expires_at)
            logger.info(f"Refresh token stored")
            
            db.session.commit()
            logger.info(f"Database changes committed")
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'message': 'Login Successful with OTP verification'
            }, 200
            
        except Exception as e:
            db.session.rollback()
            logger.error(f'OTP verification failed: {str(e)}')
            return {'message': 'OTP verification failed'}, 500