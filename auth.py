from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import uuid
import os
import re

auth_bp = Blueprint('auth', __name__)
jwt = JWTManager()

db = None
User = None

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if len(username) < 4:
        return jsonify({'message': 'Username must be at least 4 characters long.'}), 400

    if not re.match(r"^[a-zA-Z0-9_.+-]+@gmail\.com$", email):
        return jsonify({'message': 'Please use a valid Gmail address for registration.'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered.'}), 400

    user = User(username=username, email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Registration successful! You can now log in.'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"message": "Logged out successfully."}), 200

@auth_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found."}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200

@auth_bp.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.json
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found."}), 404

    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not user.check_password(old_password):
        return jsonify({"message": "Old password is incorrect."}), 400

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password updated successfully."}), 200

def configure_auth(app, _db, _User):
    global db, User
    db = _db
    User = _User

    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
    jwt.init_app(app)

    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()
