from flask import request
from flask_restx import Resource, Namespace

from helpers.decorators import auth_reqiured
from implemented import user_service

user_ns = Namespace('user')

"""Class of user's Views"""
@user_ns.route('/')
class UserView(Resource):
    @auth_reqiured
    def get(self, data):
        """Get nformation about user"""
        return data

    def post(self):
        """Create new user"""
        req_json = request.json
        user = user_service.create(req_json)
        return user, 201

    @auth_reqiured
    def patch(self, data):
        """Partically change user data"""
        req_json = request.json
        req_json["email"] = data["email"]
        user_service.update(req_json)
        return "", 204

    def put(self):
        """Fully change user data"""
        req_json = request.json
        user_service.update(req_json)
        return '', 204


@user_ns.route('/password')
class UserView(Resource):
    @auth_reqiured
    def put(self, data):
        """Change password"""
        req_json = request.json
        user_service.update_password(req_json)
        return '', 204




