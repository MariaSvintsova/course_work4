import calendar
import datetime
import hashlib
import base64
import jwt
from flask import request, abort
from flask_restx import Resource, Namespace
from helpers.constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.model.user import User
from setup_db import db
from implemented import user_service

auth_ns = Namespace('auth')


secret = 's3cR$eT'
algo = 'HS256'



@auth_ns.route('/login')
class AuthView(Resource):
    def post(self):
        """Creating new user in system"""
        req_json = request.json
        email = req_json.get('email')
        password = req_json.get('password')

        user = User.query.filter(User.email == email).first()

        if user == None:
            abort(401)

        hash_password = base64.b64encode(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), PWD_HASH_SALT, PWD_HASH_ITERATIONS))



        if user.password != hash_password:
            abort(401)

        data = {'email': email,
                'role': user.role
                }
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token': refresh_token}

        return tokens



    def put(self):
        """Check autentification"""
        req_json = request.json
        access_token = req_json.get('access_token')
        refresh_token = req_json.get('refresh_token')


        try:
            data = jwt.decode(access_token, secret, algorithms=[algo])
            data = jwt.decode(refresh_token, secret, algorithms=[algo])

        except Exception:
            abort(401)


        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token': refresh_token}

        return tokens





@auth_ns.route('/register')
class AuthView(Resource):
    def post(self):
        """Validate token"""
        req_json = request.json
        email = req_json.get('email')
        password = req_json.get('password')
        role = req_json.get('role')


        if password == None or email == None or role == None:
            abort(401)

        data = {'password': password,
                'email': email,
                'role': role}

        user_service.create(data)

        data = {'email': email,
                'role': role}

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token': refresh_token}

        return tokens

    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token')

        if refresh_token == None:
            abort(401)

        try:
            data = jwt.decode(jwt=refresh_token, key=secret, algorithms=[algo])
        except Exception:
            abort(400)

        email = data.get('email')

        user = db.session.query(User).filter(User.email == email).first()

        data = {
            'username': user.username,
            'role': user.role
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token': refresh_token}

        return tokens


