from datetime import datetime, timedelta
import uuid
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, decode_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash

from configs.utils import Config
from configs.models import db, User, RefreshToken

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # Adjust the origins according to your requirements
db.init_app(app)
jwt = JWTManager(app)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username', None)
    password = data.get('password', None)

    if not username or not password:
        return jsonify(message="Missing username or password"), 400

    user_exists = User.query.filter_by(username=username).first()

    if user_exists:
        return jsonify(message="A user with this username already exists"), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(username=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="User registered successfully"), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)

    if not username or not password:
        return jsonify(message="Missing username or password"), 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify(message="Invalid username or password"), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    decoded_refresh_token = decode_token(refresh_token)
    refresh_jti = decoded_refresh_token["jti"]
    refresh_exp = datetime.fromtimestamp(decoded_refresh_token["exp"])

    # Store the refresh token in the database
    token = RefreshToken(user_id=user.id, jti=refresh_jti, expires=refresh_exp)
    db.session.add(token)
    db.session.commit()

    response = jsonify(message="Logged in successfully.")
    response.set_cookie('access_token_cookie', access_token, max_age=timedelta(minutes=15), secure=False, httponly=True)  # Set secure=True in production
    response.set_cookie('refresh_token_cookie', refresh_token, max_age=timedelta(days=1), secure=False, httponly=True)  # Set secure=True in production
    return response, 200


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    response = jsonify(message="Access token refreshed.")
    response.set_cookie('access_token_cookie', access_token, max_age=timedelta(minutes=15), secure=False, httponly=True)  # Set secure=True in production
    return response, 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()
    return jsonify(username=user.username, message="This is a protected route"), 200


if __name__ == '__main__':
    app.run(debug=True)
