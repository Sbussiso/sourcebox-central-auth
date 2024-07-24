from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set token expiry time

api = Api(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    premium_status = db.Column(db.Boolean, default=False)
    history = db.relationship('UserHistory', backref='user', lazy=True)

class UserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(150))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class PlatformUpdates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title =  db.Column(db.String(150), unique=True)
    content = db.Column(db.String(150), unique=True)

class UserRegistration(Resource):
    def post(self):
        try:
            data = request.get_json()
            email = data.get('email')
            username = data.get('username')
            password = data.get('password')

            if not email or not username or not password:
                raise BadRequest("Email, username, and password are required.")

            if User.query.filter_by(email=email).first():
                return {"message": "User already exists"}, 400

            hashed_password = generate_password_hash(password)
            new_user = User(email=email, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return {"message": "User registered successfully"}, 201

        except IntegrityError:
            db.session.rollback()
            return {"message": "User already exists"}, 400
        except BadRequest as e:
            return {"message": str(e)}, 400
        except Exception as e:
            return {"message": "Something went wrong"}, 500

class UserLogin(Resource):
    def post(self):
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                raise BadRequest("Email and password are required.")

            user = User.query.filter_by(email=email).first()

            if not user or not check_password_hash(user.password, password):
                return {"message": "Invalid credentials"}, 401

            access_token = create_access_token(identity=email)
            return {"access_token": access_token}, 200

        except BadRequest as e:
            return {"message": str(e)}, 400
        except Exception as e:
            return {"message": "Something went wrong"}, 500

class RecordUserHistory(Resource):
    @jwt_required()
    def post(self):
        try:
            current_user_email = get_jwt_identity()
            data = request.get_json()
            action = data.get('action')
            
            if not action:
                raise BadRequest("Action is required.")
            
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {"message": "User not found"}, 404

            new_history = UserHistory(user_id=user.id, action=action)
            db.session.add(new_history)
            db.session.commit()

            return {"message": "User history recorded successfully"}, 201

        except BadRequest as e:
            return {"message": str(e)}, 400
        except Exception as e:
            return {"message": "Something went wrong"}, 500

    @jwt_required()
    def get(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {"message": "User not found"}, 404
            
            history_items = UserHistory.query.filter_by(user_id=user.id).all()
            history_data = [{"action": item.action, "timestamp": item.timestamp.isoformat()} for item in history_items]

            return jsonify(history_data)

        except Exception as e:
            return {"message": "Something went wrong"}, 500

class ListUsers(Resource):
    @jwt_required()
    def get(self):
        users = User.query.all()
        return jsonify([{"id": user.id, "email": user.email, "username": user.username} for user in users])

class SearchUsers(Resource):
    @jwt_required()
    def get(self):
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
            return {"message": "No search criteria provided"}, 400
        
        if user:
            return {"id": user.id, "email": user.email, "username": user.username}
        else:
            return {"message": "User not found"}, 404

class DeleteUser(Resource):
    @jwt_required()
    def delete(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return {"message": "User deleted"}, 200
        else:
            return {"message": "User not found"}, 404

class ResetUserEmail(Resource):
    @jwt_required()
    def put(self, user_id):
        new_email = request.json.get('new_email')
        user = User.query.filter_by(id=user_id).first()
        if user:
            user.email = new_email
            db.session.commit()
            return {"message": "Email updated"}, 200
        else:
            return {"message": "User not found"}, 404

class ResetUserPassword(Resource):
    @jwt_required()
    def put(self, user_id):
        new_password = request.json.get('new_password')
        user = User.query.filter_by(id=user_id).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return {"message": "Password updated"}, 200
        else:
            return {"message": "User not found"}, 404

class PlatformUpdatesResource(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        title = data.get('title')
        content = data.get('content')
        if not title or not content:
            return {"message": "Title and content are required"}, 400
        
        update = PlatformUpdates(title=title, content=content)
        db.session.add(update)
        db.session.commit()
        return {"message": "Update added"}, 201

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(RecordUserHistory, '/user_history')
api.add_resource(ListUsers, '/users')
api.add_resource(SearchUsers, '/users/search')
api.add_resource(DeleteUser, '/users/<int:user_id>')
api.add_resource(ResetUserEmail, '/users/<int:user_id>/email')
api.add_resource(ResetUserPassword, '/users/<int:user_id>/password')
api.add_resource(PlatformUpdatesResource, '/platform_updates')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
