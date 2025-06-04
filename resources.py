from flask_mail import Message
from flask_restful import Resource, reqparse,fields,marshal_with
from flask_jwt_extended import (create_access_token, create_refresh_token,jwt_required, get_jwt_identity,get_jwt)
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from model import User, TokenBlacklist, db
import pyotp, re
from flask import request
from config import Config

bcrypt = Bcrypt()

# Initialize URLSafeTimedSerializer for token generation
def get_serializer():
    return URLSafeTimedSerializer(Config.SECRET_KEY)  # Use a secure key, ideally from config

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
        mail.send(msg)
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")

def validate_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

class SignupResources(Resource):
    @marshal_with(user_fields)
    def post(self):
        args = signup_parser.parse_args()
        username = args['username']
        email = args['email']
        password = args['password']
        first_name = args.get('first_name')
        last_name = args.get('last_name')

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
        db.session.add(new_user)
        db.session.commit()
        return new_user, 201

class LoginResources(Resource):
    def post(self):
        print("Reached LoginResource POST method")
        print("Request Method:", request.method)
        print("Request URL:", request.url)
        print("Request Headers:", request.headers)
        print("Request Data (Raw):", request.get_data(as_text=True))
        print("Request JSON:", request.get_json())
        try:
            args = login_parser.parse_args()
            print("Parsed Args:", args)
        except Exception as e:
            print("Parsing Error:", str(e))
            return {'error': 'Failed to parse request', 'details': str(e)}, 400
        username = args['username']
        password = args['password']
        mfa_code = args.get('mfa_code')
        print("MFA Code Provided:", mfa_code)

        user = User.query.filter_by(username=username).first()
        print("User Found:", user.username if user else None)
        print("MFA Enabled:", user.mfa_enabled if user else None)
        print("MFA Secret:", user.mfa_secret if user else None)

        if not user or not user.password or not bcrypt.check_password_hash(user.password, password):
            return {'message': 'Invalid Username or Password'}, 401

        if user.mfa_enabled:
            print("MFA Code Provided (Again):", mfa_code)
            if not mfa_code or not pyotp.TOTP(user.mfa_secret).verify(mfa_code):
                print("MFA Verification Failed")
                return {'message': 'Invalid MFA code'}, 401
        user_id = str(user.id) if user and user.id else None
        print("User ID for Token Creation:", user_id)
        if not user_id or not user_id.strip():
            return {'message': 'Invalid User ID'}, 400
        access_token = create_access_token(identity=str(user_id), additional_claims={'username': user.username})
        print("Access Token Identity:", user_id)
        refresh_token = create_refresh_token(identity=str(user_id))
        print("Refresh Token Identity:", user_id)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Login Successful'
        }, 200

class MFASetupResources(Resource):
    @jwt_required()
    def post(self):
        print('Reached MFASetupResources POST method')
        print("Request Headers:", request.headers)
        print("Request JSON:", request.get_json(silent=True))
        print("Request Form:", request.form)
        user_id = get_jwt_identity()
        print("User ID from JWT:", user_id)
        user = User.query.get_or_404(user_id)
        print("User Email:", user.email)
        print("User MFA Secret:", user.mfa_secret)

        if not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()
            db.session.commit()
            print("New MFA Secret Generated:", user.mfa_secret)
        return {'mfa_secret': user.mfa_secret, 'provisioning_uri':
                pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(user.email, issuer_name='MyApp')}, 200

    @jwt_required()
    def put(self):
        args = mfa_parser.parse_args()
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)

        if pyotp.TOTP(user.mfa_secret).verify(args['mfa_code']):
            user.mfa_enabled = True
            db.session.commit()
            return {'message': 'MFA Enabled'}, 200
        return {'message': 'Invalid MFA code'}, 401

class TokenRefreshResources(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        print("Identity from Refresh Token:", current_user)
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
        print("Request Headers", request.headers)
        user_id = get_jwt_identity()
        print("Identity from Profile Request:", user_id)

        if not isinstance(user_id, str):
            return {'message': 'Invalid user ID type'}, 422

        try:
            user = User.query.get_or_404(int(user_id))
            return user, 200
        except ValueError:
            return {'message': 'Invalid user ID format'}, 422
        except Exception as e:
            return {'message': str(e)}, 400

class GoogleLoginResources(Resource):
    def get(self):
        print('Reached GoogleLoginResources GET method')
        from app import oauth
        google = oauth.create_client('google')
        redirect_uri = 'https://localhost:5000/auth/google/callback'
        print(f"Redirect URI: {redirect_uri}")
        return google.authorize_redirect(redirect_uri)

class GoogleCallbackResources(Resource):
    def get(self):
        print('Reached GoogleCallbackResources GET method')
        from app import oauth
        google = oauth.create_client('google')
        print("Request Args:", request.args)
        token = google.authorize_access_token()
        print("Access Token:", token)
        user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        print("User Info:", user_info)

        user = User.query.filter_by(oauth_provider='google', oauth_id=user_info['sub']).first()
        if not user:
            user = User(
                username=user_info['email'].split('@')[0],
                email=user_info['email'],
                first_name=user_info.get('given_name'),
                last_name=user_info.get('family_name'),
                oauth_provider='google',
                oauth_id=user_info['sub']
            )
            db.session.add(user)
            db.session.commit()

        user_id = str(user.id)
        print("User ID for Token Creation:", user_id)
        if not user_id or not user_id.strip():
            return {'message': 'Invalid User ID'}, 400

        access_token = create_access_token(identity=user_id, additional_claims={'username': user.username})
        print("Access Token Identity:", user_id)
        refresh_token = create_refresh_token(identity=user_id)
        print("Refresh Token Identity:", user_id)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Google Login Successful'
        }, 200
