import uuid
import logging
from flask_restful import Resource
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from model import User, db
from .utils import (
    forgot_password_parser, reset_password_parser, 
    get_serializer, send_email, bcrypt
)
from config import Config

logger = logging.getLogger(__name__)

class ForgotPasswordResource(Resource):
    def post(self):
        try:
            args = forgot_password_parser.parse_args()
            email = args['email']
            user = User.query.filter_by(email=email).first()

            if not user:
                logger.warning(f"User not found for email in reset token: {email}")
                return {'message': 'User not found'}, 401

            if user:
                logger.info(f'User with email:{email} found')
                serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
                token = serializer.dumps(user.email)
                reset_url = f'{Config.BASE_URL}/reset-password/{token}'
                send_email(user.email, 'Reset Your password', f'Reset link: {reset_url}')
                return {'message': 'Password reset email sent'}, 200
            return {'message': 'User not found'}, 404
        except Exception as e:
            logger.error(f"Error in forgot password: {str(e)}")
            return {'message': 'Email sending failed'}, 500

class ResetPasswordResource(Resource):
    def post(self, token):
        try:
            serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
            email = serializer.loads(token, max_age=600)
            user = User.query.filter_by(email=email).first()

            if not user:
                logger.warning(f"User not found for email in reset token: {email}")
                return {'message': 'User not found'}, 401

            args = reset_password_parser.parse_args()
            user.password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
            user.token_id = str(uuid.uuid4())
            db.session.commit()
            logger.info(f"Password reset successful for user: {email}")
            return {'message': 'Password reset successful'}, 200
        except SignatureExpired:
            logger.error(f"Reset token expired for token: {token}")
            return {'message': 'Reset token has expired'}, 400
        except BadSignature:
            logger.error(f"Invalid reset token: {token}")
            return {'message': 'Invalid reset token'}, 400
        except Exception as e:
            logger.error(f"Error in reset password: {str(e)}")
            db.session.rollback()
            return {'message': 'Invalid or Expired token'}, 400