from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest
from marshmallow import Schema, fields
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
import os
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

api = Api(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    premium_status = db.Column(db.Boolean, default=False)
    history = db.relationship('UserHistory', backref='user', lazy=True)
    packs = db.relationship('Packman', backref='user', lazy=True)

class UserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(150))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class PlatformUpdates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), unique=True)
    content = db.Column(db.String(150), unique=True)

class Packman(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pack_name = db.Column(db.String(150), nullable=False)
    packs = db.relationship('PackmanPack', backref='packman', lazy=True)

class PackmanPack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    packman_id = db.Column(db.Integer, db.ForeignKey('packman.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    data_type = db.Column(db.String(50), nullable=False)  # "link" or "file"
    filename = db.Column(db.String(255), nullable=True)

class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_relationships = True
        load_instance = True

class UserHistorySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = UserHistory
        include_relationships = True
        load_instance = True

class PlatformUpdatesSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = PlatformUpdates
        include_relationships = True
        load_instance = True

class PackmanSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Packman
        include_relationships = True
        load_instance = True

class PackmanPackSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = PackmanPack
        include_relationships = True
        load_instance = True

user_schema = UserSchema()
users_schema = UserSchema(many=True)
user_history_schema = UserHistorySchema()
user_histories_schema = UserHistorySchema(many=True)
platform_update_schema = PlatformUpdatesSchema()
platform_updates_schema = PlatformUpdatesSchema(many=True)
packman_schema = PackmanSchema()
packmans_schema = PackmanSchema(many=True)
packman_pack_schema = PackmanPackSchema()
packman_packs_schema = PackmanPackSchema(many=True)

class UserRegistration(Resource):
    def post(self):
        logger.info("Entered UserRegistration post method")
        try:
            data = request.get_json()
            logger.info(f"Received registration data: {data}")
            email = data.get('email')
            username = data.get('username')
            password = data.get('password')

            if not email or not username or not password:
                logger.error("Email, username, and password are required")
                return {"message": "Email, username, and password are required"}, 400

            if User.query.filter_by(email=email).first():
                logger.error(f"User with email {email} already exists")
                return {"message": "User already exists"}, 400

            hashed_password = generate_password_hash(password)
            new_user = User(email=email, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            logger.info(f"User {email} registered successfully")
            return user_schema.dump(new_user), 201

        except IntegrityError:
            db.session.rollback()
            logger.error(f"Integrity error for user {email}")
            return {"message": "User already exists"}, 400
        except BadRequest as e:
            logger.error(f"Bad request: {e}")
            return {"message": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error during user registration: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class UserLogin(Resource):
    def post(self):
        logger.info("Entered UserLogin post method")
        try:
            data = request.get_json()
            logger.info(f"Received login data: {data}")
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                logger.error("Email and password are required")
                return {"message": "Email and password are required"}, 400

            user = User.query.filter_by(email=email).first()

            if not user or not check_password_hash(user.password, password):
                logger.error(f"Invalid credentials for email {email}")
                return {"message": "Invalid credentials"}, 401

            access_token = create_access_token(identity=email)
            logger.info(f"User {email} logged in successfully")
            return {"access_token": access_token}, 200

        except BadRequest as e:
            logger.error(f"Bad request: {e}")
            return {"message": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error during user login: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class RecordUserHistory(Resource):
    @jwt_required()
    def post(self):
        logger.info("Entered RecordUserHistory post method")
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
            logger.info(f"Received history data: {data} from user {current_user_email}")
            action = data.get('action')
            
            if not action:
                logger.error("Action is required")
                return {"message": "Action is required"}, 400
            
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404

            new_history = UserHistory(user_id=user.id, action=action)
            db.session.add(new_history)
            db.session.commit()

            logger.info(f"Recorded history for user {current_user_email}: {action}")
            return user_history_schema.dump(new_history), 201

        except BadRequest as e:
            logger.error(f"Bad request: {e}")
            return {"message": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error recording user history: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

    @jwt_required()
    def get(self):
        logger.info("Entered RecordUserHistory get method")
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404
            
            history_items = UserHistory.query.filter_by(user_id=user.id).all()
            history_data = user_histories_schema.dump(history_items)

            logger.info(f"Fetched history for user {current_user_email}")
            return jsonify(history_data)

        except Exception as e:
            logger.error(f"Unexpected error fetching user history: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class ListUsers(Resource):
    @jwt_required()
    def get(self):
        logger.info("Entered ListUsers get method")
        try:
            users = User.query.all()
            user_list = users_schema.dump(users)
            logger.info("Fetched list of users")
            return jsonify(user_list)
        except Exception as e:
            logger.error(f"Unexpected error listing users: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class SearchUsers(Resource):
    @jwt_required()
    def get(self):
        logger.info("Entered SearchUsers get method")
        try:
            username = request.args.get('username')
            email = request.args.get('email')
            user_id = request.args.get('id')
            
            if username:
                user = User.query.filter_by(username=username).first()
            elif email:
                user = User.query.filter_by(email=email).first()
            elif user_id:
                user = User.query.filter_by(id=user_id).first()
            else:
                logger.error("No search criteria provided")
                return {"message": "No search criteria provided"}, 400
            
            if user:
                user_data = user_schema.dump(user)
                logger.info(f"Found user: {user_data}")
                return jsonify(user_data)
            else:
                logger.error("User not found")
                return {"message": "User not found"}, 404
        except Exception as e:
            logger.error(f"Unexpected error searching users: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class DeleteUser(Resource):
    @jwt_required()
    def delete(self, user_id):
        logger.info(f"Entered DeleteUser delete method for user_id {user_id}")
        try:
            user = User.query.filter_by(id=user_id).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                logger.info(f"Deleted user with id {user_id}")
                return {"message": "User deleted"}, 200
            else:
                logger.error(f"User with id {user_id} not found")
                return {"message": "User not found"}, 404
        except Exception as e:
            logger.error(f"Unexpected error deleting user: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class ResetUserEmail(Resource):
    @jwt_required()
    def put(self, user_id):
        logger.info(f"Entered ResetUserEmail put method for user_id {user_id}")
        try:
            new_email = request.json.get('new_email')
            user = User.query.filter_by(id=user_id).first()
            if user:
                user.email = new_email
                db.session.commit()
                logger.info(f"Updated email for user with id {user_id} to {new_email}")
                return {"message": "Email updated"}, 200
            else:
                logger.error(f"User with id {user_id} not found")
                return {"message": "User not found"}, 404
        except Exception as e:
            logger.error(f"Unexpected error resetting user email: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class ResetUserPassword(Resource):
    @jwt_required()
    def put(self, user_id):
        logger.info(f"Entered ResetUserPassword put method for user_id {user_id}")
        try:
            new_password = request.json.get('new_password')
            user = User.query.filter_by(id=user_id).first()
            if user:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                logger.info(f"Updated password for user with id {user_id}")
                return {"message": "Password updated"}, 200
            else:
                logger.error(f"User with id {user_id} not found")
                return {"message": "User not found"}, 404
        except Exception as e:
            logger.error(f"Unexpected error resetting user password: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class PlatformUpdatesResource(Resource):
    @jwt_required()
    def post(self):
        logger.info("Entered PlatformUpdatesResource post method")
        try:
            data = request.get_json()
            logger.info(f"Received platform update data: {data}")
            title = data.get('title')
            content = data.get('content')
            if not title or not content:
                logger.error("Title and content are required")
                return {"message": "Title and content are required"}, 400
            
            update = PlatformUpdates(title=title, content=content)
            db.session.add(update)
            db.session.commit()
            logger.info("Added platform update")
            return platform_update_schema.dump(update), 201
        except Exception as e:
            logger.error(f"Unexpected error posting platform update: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

class PackmanPackResource(Resource):
    @jwt_required()
    def post(self):
        logger.info("Entered PackmanPackResource post method")
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
            
            # Log the received data
            logger.info(f"Received data: {data}")
            
            pack_name = data.get('pack_name')
            contents = data.get('contents')

            if not pack_name or not contents:
                logger.error("Pack name and contents are required")
                return {"message": "Pack name and contents are required"}, 400

            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404

            packman_entry = Packman(user_id=user.id, pack_name=pack_name)
            db.session.add(packman_entry)
            db.session.commit()

            for content in contents:
                data_type = content.get('data_type')
                text_content = content.get('content')
                filename = content.get('filename')

                if not data_type or not text_content:
                    logger.error("Data type and content are required for each entry")
                    return {"message": "Data type and content are required for each entry"}, 400

                # Check and truncate content if necessary
                if len(text_content) > 65535:  # Assuming MySQL TEXT type limit, adjust as needed
                    logger.warning(f"Content length exceeds limit for entry: {content}")
                    text_content = text_content[:65535]

                pack_entry = PackmanPack(
                    packman_id=packman_entry.id,
                    content=text_content,
                    data_type=data_type,
                    filename=filename
                )
                db.session.add(pack_entry)

            db.session.commit()

            logger.info(f"Processed pack for user {current_user_email}")
            return packman_schema.dump(packman_entry), 201
        except Exception as e:
            logger.error(f"Unexpected error processing pack: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500


class PackmanListPacks(Resource):
    @jwt_required()
    def get(self):
        logger.info("Entered PackmanListPacks get method")
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404

            packs = Packman.query.filter_by(user_id=user.id).all()
            pack_list = packmans_schema.dump(packs)

            logger.info(f"Fetched packs for user {current_user_email}")
            return jsonify(pack_list)
        except Exception as e:
            logger.error(f"Unexpected error listing packs: {e}", exc_info=True)
            return {"message": "Something went wrong"}, 500

# Register API resources
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(RecordUserHistory, '/user_history')
api.add_resource(ListUsers, '/users')
api.add_resource(SearchUsers, '/users/search')
api.add_resource(DeleteUser, '/users/<int:user_id>')
api.add_resource(ResetUserEmail, '/users/<int:user_id>/email')
api.add_resource(ResetUserPassword, '/users/<int:user_id>/password')
api.add_resource(PlatformUpdatesResource, '/platform_updates')
api.add_resource(PackmanPackResource, '/packman/pack')
api.add_resource(PackmanListPacks, '/packman/list_packs')

# Error handler for 404 Not Found
@app.errorhandler(404)
def resource_not_found(e):
    logger.error(f"Resource not found: {e}")
    return jsonify({"message": "Resource not found"}), 404

# Error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"message": "Internal server error"}), 500

# Error handler for SQLAlchemy errors
@app.errorhandler(SQLAlchemyError)
def handle_sqlalchemy_error(e):
    logger.error(f"Database error: {e}", exc_info=True)
    db.session.rollback()
    return jsonify({"message": "Database error"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
