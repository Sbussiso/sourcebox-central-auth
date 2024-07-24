from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

api = Api(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

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
                return {"message": "User with this email already exists"}, 400

            hashed_password = generate_password_hash(password)
            new_user = User(email=email, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return {"message": "User registered successfully"}, 201

        except IntegrityError:
            db.session.rollback()
            return {"message": "User with this email already exists"}, 400
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

class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user = get_jwt_identity()
            return {"message": f"Hello {current_user}"}, 200
        except Exception as e:
            return {"message": "Something went wrong"}, 500

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ProtectedResource, '/protected')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
