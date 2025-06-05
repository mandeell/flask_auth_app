import uuid
from flask_mail import Message
from flask_restful import Resource, reqparse,fields,marshal_with
from flask_jwt_extended import (create_access_token, create_refresh_token,jwt_required, get_jwt_identity,get_jwt)
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from model import User, TokenBlacklist, db
import pyotp
from flask import request
from config import Config
from email_validator import validate_email as check_email, EmailNotValidError

bcrypt = Bcrypt()

# Initialize URLSafeTimedSerializer for token generation
def get_serializer():
    return URLSafeTimedSerializer(Config.SECRET_KEY)  # Use a secure key, ideally from config

def validate_email(email):
    try:
        check_email(email)
        print(f'Email address {email} is valid')
        return True
    except EmailNotValidError as e:
        print(f'Email validation for {email}: {str(e)}')
        return False

# Output fields
user_fields = {
    'id': fields.Integer,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'oauth_provider': fields.String,
    'mfa_enabled': fields.Boolean,
}

# Parsers
signup_parser = reqparse.RequestParser()
signup_parser.add_argument('username', type=str, required=True, help='Username is required')
signup_parser.add_argument('email', type=str, required=True, help='Email is required')
signup_parser.add_argument('password', type=str, required=True, help='Password is required')
signup_parser.add_argument('first_name', type=str)
signup_parser.add_argument('last_name', type=str)

login_parser = reqparse.RequestParser()
login_parser.add_argument('username', type=str, required=True, help='Username is required')
login_parser.add_argument('password', type=str, required=True, help='Password is required')
login_parser.add_argument('mfa_code', type=str, location='json')

mfa_parser = reqparse.RequestParser()
mfa_parser.add_argument('mfa_code', type=str, required=True, help='MFA code is required')

forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, required=True, help='Email is required')

reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')

def send_email(to, subject, template):
    """Helper function to send emails"""
    from app import mail
    msg = Message(
        subject=subject,
        sender=Config.MAIL_DEFAULT_SENDER,
        recipients=[to],
        html=template
    )
    try:
        print(
            f'Sending email to {to} using SMTP {Config.MAIL_SERVER}:{Config.MAIL_PORT} '
            f'with username {Config.MAIL_USERNAME}')
        mail.send(msg)
        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {str(e)}')
        raise Exception(f"Failed to send email: {str(e)}")


class SignupResources(Resource):
    @marshal_with(user_fields)
    def post(self):
        try:
            args = signup_parser.parse_args()
            print('Parsed Args', args)
            username = args['username']
            email = args['email']
            password = args['password']
            first_name = args.get('first_name')
            last_name = args.get('last_name')


            print(f"Checking email: {email}")
            if not validate_email(email):
                return {'message': 'Invalid email format'}, 400
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                return {'message': 'Username already exists'}, 400
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                is_active=False,
            )
            serializer = get_serializer()
            token = serializer.dumps(new_user.email)
            confirmation_url = f'https://localhost:5000/confirm/{token}'
            send_email(new_user.email, 'Confirm Your Email', f'Please confirm your email: {confirmation_url}')
            db.session.add(new_user)
            db.session.commit()
            return new_user, 201
        except Exception as e:
            return {'message': 'Server error', 'error': str(e)}, 500

class LoginResources(Resource):
    def post(self):
        try:
            args = login_parser.parse_args()
        except Exception as e:
            return {'error': 'Failed to parse request', 'details': str(e)}, 400
        username = args['username']
        password = args['password']
        mfa_code = args.get('mfa_code')

        user = User.query.filter_by(username=username).first()
        if not user or not user.password or not bcrypt.check_password_hash(user.password, password) or not user.is_active:
            return {'message': 'Invalid Username or Password'}, 401
        if not user.is_active:
            return {'message': 'Account not activated. Please confirm your email.'}, 403

        if user.mfa_enabled:
            if not mfa_code or not pyotp.TOTP(user.mfa_secret).verify(mfa_code):
                return {'message': 'Invalid MFA code'}, 401

        # user_id = str(user.id) if user and user.id else None
        # if not user_id or not user_id.strip():
        #     return {'message': 'Invalid User ID'}, 400
        access_token = create_access_token(identity=user.token_id, additional_claims={'username': user.username})
        refresh_token = create_refresh_token(identity=user.token_id, additional_claims={'username': user.username})
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Login Successful'
        }, 200

class MFASetupResources(Resource):
    @jwt_required()
    def post(self):
        print("Reached /mfa POST endpoint")
        user_id = get_jwt_identity()
        print(f"JWT Identity: {user_id}")
        user = User.query.filter_by(token_id=user_id).first()
        print(f"Found user: {user.username}")
        if not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()
            db.session.commit()
        return {'mfa_secret': user.mfa_secret, 'provisioning_uri':
                pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(user.email, issuer_name='MyApp')}, 200

    @jwt_required()
    def put(self):
        args = mfa_parser.parse_args()
        user_id = get_jwt_identity()
        user = User.query.filter_by(token_id=user_id).first()

        if pyotp.TOTP(user.mfa_secret).verify(args['mfa_code']):
            user.mfa_enabled = True
            db.session.commit()
            return {'message': 'MFA Enabled'}, 200
        return {'message': 'Invalid MFA code'}, 401

class TokenRefreshResources(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        if not isinstance(current_user, str):
            return {'message': 'Invalid identity type'}, 422
        new_access_token = create_access_token(identity=str(current_user))
        return {'access_token': new_access_token}, 200

class LogoutResources(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        db.session.add(TokenBlacklist(jti=jti))
        db.session.commit()
        return {'message': 'Logout Successful'}, 200

class ProfileResources(Resource):
    @jwt_required()
    @marshal_with(user_fields)
    def get(self):
        user_id = get_jwt_identity()

        if not isinstance(user_id, str):
            return {'message': 'Invalid user ID type'}, 422

        try:
            user = User.query.filter_by(token_id=user_id).first_or_404()
            return user, 200
        except ValueError:
            return {'message': 'Invalid user ID format'}, 422
        except Exception as e:
            return {'message': str(e)}, 400

class GoogleLoginResources(Resource):
    def get(self):
        from app import oauth
        google = oauth.create_client('google')
        redirect_uri = 'https://localhost:5000/auth/google/callback'
        return google.authorize_redirect(redirect_uri)

class GoogleCallbackResources(Resource):
    def get(self):
        try:
            from app import oauth
            google = oauth.create_client('google')
            token = google.authorize_access_token()
            user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

            # First, check if user exists by OAuth credentials
            user = User.query.filter_by(oauth_provider='google', oauth_id=user_info['sub']).first()

            if user:
                # User exists with OAuth, proceed with login
                access_token = create_access_token(identity=user.token_id,
                                                   additional_claims={'username': user.username})
                refresh_token = create_refresh_token(identity=user.token_id,
                                                     additional_claims={'username': user.username})
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'message': 'Google Login Successful'
                }, 200

            # Check if user exists with same email (from regular signup)
            existing_user = User.query.filter_by(email=user_info['email']).first()

            if existing_user:
                # Update existing user to link with Google OAuth
                existing_user.oauth_provider = 'google'
                existing_user.oauth_id = user_info['sub']
                # Optionally update name fields if they're empty
                if not existing_user.first_name:
                    existing_user.first_name = user_info.get('given_name')
                if not existing_user.last_name:
                    existing_user.last_name = user_info.get('family_name')

                db.session.commit()

                access_token = create_access_token(identity=existing_user.token_id,
                                                    additional_claims={'username': existing_user.username})
                refresh_token = create_refresh_token(identity=existing_user.token_id,
                                                        additional_claims={'username': existing_user.username})
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'message': 'Google account linked successfully'
                }, 200

            # Create new user if no existing user found
            base_username = user_info['email'].split('@')[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f'{base_username}{counter}'
                counter += 1

            user = User(
                username=username,
                email=user_info['email'],
                first_name=user_info.get('given_name'),
                last_name=user_info.get('family_name'),
                oauth_provider='google',
                oauth_id=user_info['sub'],
                is_active=True  # OAuth users are automatically active
            )
            db.session.add(user)
            db.session.commit()

            access_token = create_access_token(identity=user.token_id,
                                                additional_claims={'username': user.username})
            refresh_token = create_refresh_token(identity=user.token_id,
                                                additional_claims={'username': user.username})
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'message': 'Google Login Successful'
            }, 200

        except Exception as e:
            db.session.rollback()
            print(f'Error in Google OAuth Callback: {str(e)}')
            return {'message': 'Server error', 'error': str(e)}, 500

class ConfirmEmailResource(Resource):
    def get(self, token):
        serializer = get_serializer()
        try:
            email = serializer.loads(token, max_age=3600)
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_active = True
                db.session.commit()
                return {'message': 'Email Confirmed'}, 200
            return {'message': 'User not found'}, 400
        except Exception:
            return {'message': 'Invalid or Expired token'}, 400

class ForgotPasswordResource(Resource):
    def post(self):
        args = forgot_password_parser.parse_args()
        email =     args['email']
        user = User.query.filter_by(email=email).first()
        if user:
            serializer = get_serializer()
            token = serializer.dumps(user.email)
            reset_url = f'https://localhost:5000/reset-password/{token}'
            send_email(user.email, 'Reset Your password', f'Reset link: {reset_url}')
            return {'message': 'Password reset email sent'}, 200
        return {'message': 'User not found'}, 404

class ResetPasswordResource(Resource):
    def post(self, token):
        serializer = get_serializer()
        try:
            email = serializer.loads(token, max_age=3600)
            user = User.query.filter_by(email=email).first()
            if user:
                args = reset_password_parser.parse_args()
                user.password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
                user.token_id = str(uuid.uuid4())
                db.session.commit()
                return {'message': 'Password reset successful'}, 200
            return {'message': 'User not found'}, 404
        except Exception:
            return {'message': 'Invalid or Expired token'}, 400

class ResendConfirmationResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help='Email address is required')
        args = parser.parse_args()
        email = args['email']
        user = User.query.filter_by(email=email).first()
        if user and not user.is_active:
            serializer = get_serializer()
            token = serializer.dumps(user.email)
            confirmation_url = f'https://localhost:5000/confirm/{token}'
            send_email(user.email, 'Confirm Your Email', f'Please confirm your email: {confirmation_url}')
            return {'message': 'Confirmation email sent'}, 200
        return {'message': 'User not found or already active'}, 404

