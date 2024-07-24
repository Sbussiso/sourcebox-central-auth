from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

api = Api(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class UserRegistration(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                raise BadRequest("Username and password are required.")

            if User.query.filter_by(username=username).first():
                return {"message": "User already exists"}, 400

            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
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
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                raise BadRequest("Username and password are required.")

            user = User.query.filter_by(username=username).first()

            if not user or not check_password_hash(user.password, password):
                return {"message": "Invalid credentials"}, 401

            access_token = create_access_token(identity=username)
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
    app.run(debug=True)
