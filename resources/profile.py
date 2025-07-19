from flask_restful import Resource, marshal_with
from flask_jwt_extended import jwt_required, get_jwt_identity
from model import User
from .utils import user_fields

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