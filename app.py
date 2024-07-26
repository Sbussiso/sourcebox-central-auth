from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import BadRequest
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
    pack_name = db.Column(db.String(150), nullable=False)
    packman_id = db.Column(db.Integer, db.ForeignKey('packman.id'), nullable=False)
    web_data = db.relationship('PackmanWebData', backref='pack', lazy=True)
    files = db.relationship('PackmanUserFile', backref='pack', lazy=True)

class PackmanWebData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    pack_id = db.Column(db.Integer, db.ForeignKey('packman_pack.id'), nullable=False)

class PackmanUserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    pack_id = db.Column(db.Integer, db.ForeignKey('packman_pack.id'), nullable=False)

class UserRegistration(Resource):
    def post(self):
        try:
            data = request.get_json()
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
            return {"message": "User registered successfully"}, 201

        except IntegrityError:
            db.session.rollback()
            logger.error(f"Integrity error for user {email}")
            return {"message": "User already exists"}, 400
        except BadRequest as e:
            logger.error(f"Bad request: {e}")
            return {"message": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error during user registration: {e}")
            return {"message": "Something went wrong"}, 500

class UserLogin(Resource):
    def post(self):
        try:
            data = request.get_json()
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
            logger.error(f"Unexpected error during user login: {e}")
            return {"message": "Something went wrong"}, 500

class RecordUserHistory(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
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
            return {"message": "User history recorded successfully"}, 201

        except BadRequest as e:
            logger.error(f"Bad request: {e}")
            return {"message": str(e)}, 400
        except Exception as e:
            logger.error(f"Unexpected error recording user history: {e}")
            return {"message": "Something went wrong"}, 500

    @jwt_required()
    def get(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404
            
            history_items = UserHistory.query.filter_by(user_id=user.id).all()
            history_data = [{"action": item.action, "timestamp": item.timestamp.isoformat()} for item in history_items]

            logger.info(f"Fetched history for user {current_user_email}")
            return jsonify(history_data)

        except Exception as e:
            logger.error(f"Unexpected error fetching user history: {e}")
            return {"message": "Something went wrong"}, 500

class ListUsers(Resource):
    @jwt_required()
    def get(self):
        try:
            users = User.query.all()
            user_list = [{"id": user.id, "email": user.email, "username": user.username} for user in users]
            logger.info("Fetched list of users")
            return jsonify(user_list)
        except Exception as e:
            logger.error(f"Unexpected error listing users: {e}")
            return {"message": "Something went wrong"}, 500

class SearchUsers(Resource):
    @jwt_required()
    def get(self):
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
                user_data = {"id": user.id, "email": user.email, "username": user.username}
                logger.info(f"Found user: {user_data}")
                return jsonify(user_data)
            else:
                logger.error("User not found")
                return {"message": "User not found"}, 404
        except Exception as e:
            logger.error(f"Unexpected error searching users: {e}")
            return {"message": "Something went wrong"}, 500

class DeleteUser(Resource):
    @jwt_required()
    def delete(self, user_id):
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
            logger.error(f"Unexpected error deleting user: {e}")
            return {"message": "Something went wrong"}, 500

class ResetUserEmail(Resource):
    @jwt_required()
    def put(self, user_id):
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
            logger.error(f"Unexpected error resetting user email: {e}")
            return {"message": "Something went wrong"}, 500

class ResetUserPassword(Resource):
    @jwt_required()
    def put(self, user_id):
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
            logger.error(f"Unexpected error resetting user password: {e}")
            return {"message": "Something went wrong"}, 500

class PlatformUpdatesResource(Resource):
    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            title = data.get('title')
            content = data.get('content')
            if not title or not content:
                logger.error("Title and content are required")
                return {"message": "Title and content are required"}, 400
            
            update = PlatformUpdates(title=title, content=content)
            db.session.add(update)
            db.session.commit()
            logger.info("Added platform update")
            return {"message": "Update added"}, 201
        except Exception as e:
            logger.error(f"Unexpected error posting platform update: {e}")
            return {"message": "Something went wrong"}, 500

class PackmanWebPack(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
            pack_name = data.get('pack_name')
            docs = data.get('docs')

            if not pack_name or not docs:
                logger.error("Pack name and docs are required")
                return {"message": "Pack name and docs are required"}, 400

            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404

            packman_entry = Packman(user_id=user.id, pack_name=pack_name)
            db.session.add(packman_entry)
            db.session.commit()

            for doc in docs:
                web_data_entry = PackmanWebData(
                    url=doc['url'],
                    content=doc['content'],
                    pack_id=packman_entry.id
                )
                db.session.add(web_data_entry)
            db.session.commit()

            logger.info(f"Processed web pack for user {current_user_email}")
            return {"message": "Link processed successfully"}, 201
        except Exception as e:
            logger.error(f"Unexpected error processing web pack: {e}")
            return {"message": "Something went wrong"}, 500

class PackmanFilePack(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
            pack_name = data.get('pack_name')
            filename = data.get('filename')
            filepath = data.get('filepath')

            if not pack_name or not filename or not filepath:
                logger.error("Pack name, filename, and filepath are required")
                return {"message": "Pack name, filename, and filepath are required"}, 400

            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                logger.error(f"User with email {current_user_email} not found")
                return {"message": "User not found"}, 404

            packman_entry = Packman(user_id=user.id, pack_name=pack_name)
            db.session.add(packman_entry)
            db.session.commit()

            file_data_entry = PackmanUserFile(
                filename=filename,
                filepath=filepath,
                pack_id=packman_entry.id
            )
            db.session.add(file_data_entry)
            db.session.commit()

            logger.info(f"Processed file pack for user {current_user_email}")
            return {"message": "File processed successfully"}, 201
        except Exception as e:
            logger.error(f"Unexpected error processing file pack: {e}")
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
api.add_resource(PackmanWebPack, '/packman/web_pack')
api.add_resource(PackmanFilePack, '/packman/file_pack')

# Error handler for 404 Not Found
@app.errorhandler(404)
def resource_not_found(e):
    logger.error(f"Resource not found: {e}")
    return jsonify({"message": "Resource not found"}), 404

# Error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"message": "Internal server error"}), 500

# Error handler for SQLAlchemy errors
@app.errorhandler(SQLAlchemyError)
def handle_sqlalchemy_error(e):
    logger.error(f"Database error: {e}")
    db.session.rollback()
    return jsonify({"message": "Database error"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
