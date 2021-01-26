"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os, json
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt_identity
)
#install flask-jwt-simple for import to work

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():
    table = User.query.all()
    table = list(map(lambda x: x.serialize(), table))
    return jsonify(table), 200

@app.route('/user', methods=['POST'])
def post_user():
    body = request.json
    new_user = User(username=body['username'], email=body['email'], password=body['password'], is_active=False)    
    db.session.add(new_user)
    db.session.commit()
    added = User.query.filter_by(email=body['email'])
    if added:
        return jsonify(f"User {body['username']} was created"), 200
    else:
        return jsonify('User could not be created'), 401    

@app.route('/login', methods=['POST'])
def login():
    credentials = request.json
    email = credentials.get('email', None)
    password = credentials.get('password', None)
    user = User.query.filter_by(email=email, password=password).first()      
    if user is None:
        return jsonify("Invalid email or password"), 401
    ret = {
        'jwt': create_jwt(identity=user.id),
        'business_id': user.id
    }      

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
