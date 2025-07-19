from flask_restful import Resource, reqparse
from model import User, db
from .utils import get_serializer, send_email
from config import Config

class ConfirmEmailResource(Resource):
    def get(self, token):
        serializer = get_serializer()
        try:
            email = serializer.loads(token, max_age=3600)
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_active = True
                db.session.commit()
                return {'message': f'Email Confirmed, Go back to login'}, 200
            return {'message': 'User not found'}, 400
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
            confirmation_url = f'{Config.BASE_URL}/confirm/{token}'
            send_email(user.email, 'Confirm Your Email', f'Please confirm your email: {confirmation_url}')
            return {'message': 'Confirmation email sent'}, 200
        return {'message': 'User not found or already active'}, 404