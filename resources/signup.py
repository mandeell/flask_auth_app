import logging
from flask_restful import Resource
from model import User, db
from .utils import (
    signup_parser, validate_email, save_profile_picture, 
    get_serializer, send_email, bcrypt
)
from config import Config

logger = logging.getLogger(__name__)

class SignupResources(Resource):
    def post(self):
        try:
            args = signup_parser.parse_args()
            logger.info('Parsed signup arguments')
            username = args['username']
            email = args['email']
            password = args['password']
            first_name = args.get('first_name')
            last_name = args.get('last_name')
            phone_number = args.get('phone_number')
            profile_picture_b64 = args.get('profile_picture')

            logger.info(f"Checking email: {email}")
            if not validate_email(email):
                return {'message': 'Invalid email format'}, 400
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                logger.warning("User already exists")
                return {'message': 'Username already exists'}, 400
            
            # Check if phone number already exists
            if phone_number and User.query.filter_by(phone_number=phone_number).first():
                return {'message': 'Phone number already exists'}, 400
                
            logger.info("Creating hashed password")
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            logger.info("Creating new user object")
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                is_active=False,
            )
            
            # Add user to database first to get ID for profile picture
            db.session.add(new_user)
            db.session.flush()  # Get the ID without committing
            
            # Handle profile picture if provided
            if profile_picture_b64:
                profile_picture_filename = save_profile_picture(profile_picture_b64, new_user.id)
                if profile_picture_filename:
                    new_user.profile_picture = profile_picture_filename
            logger.info("Generating confirmation token")
            serializer = get_serializer()
            token = serializer.dumps(new_user.email)
            confirmation_url = f'{Config.BASE_URL}/confirm/{token}'
            logger.info(f"Sending confirmation email to: {email}")
            try:
                send_email(new_user.email, 'Confirm Your Email', f'Please confirm your email: '
                                                                 f'{confirmation_url}')
                logger.info("Email sent successfully")
            except Exception as e:
                logger.error(f"Email sending failed: {str(e)}")

            new_user_dict = {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'first_name': new_user.first_name,
                'last_name': new_user.last_name,
                'is_active': new_user.is_active
            }
            logger.info("Adding user to database")
            db.session.add(new_user)
            logger.info("Committing to database")
            db.session.commit()
            logger.info("User created successfully")
            return {'message': f'Email sent to {new_user.email} Confirm your Email to Create Account'}, 200
        except Exception as e:
            logger.error(f"Exception caught: {str(e)}")
            logger.error(f"Exception type: {type(e)}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            db.session.rollback()  # Important: rollback on error
            return {'message': 'Database error occurred during signup'}, 500