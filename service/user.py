import base64
import hashlib

from flask import abort

from dao.model.user import UserSchema
from dao.user import UserDAO
from helpers.constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS

user_schema = UserSchema()
users_schema = UserSchema(many=True)
class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return user_schema.dump(self.dao.get_one(uid))

    def get_all(self):
        return users_schema.dump(self.dao.get_all())

    def create(self, user_d):
        passw = user_d.get('password')
        new_pass = self.get_hash(passw)
        user_d['password'] = new_pass

        return user_schema.dump(self.dao.create(user_d))

    def update(self, user_d):
        user = self.dao.get_mail(user_d['mail'])
        if 'surname' in user_d.keys():
            user.surname = user_d['surname']
        if 'name' in user_d.keys():
            user.name = user_d['name']
        if 'password' in user_d.keys():
            user.password = user_d['password']
        if 'favorite_genre' in user_d.keys():
            user.favorite_genre = user_d['favorite_genre']
        self.dao.update(user_d)
        return ''

    def update_password(self, user_d):
        user = self.dao.get_mail(user_d['email'])
        new_password = user_d['new_password']
        old_password = user_d['old_password']

        if user == None:
            abort(401)

        hash_old_password = base64.b64encode(hashlib.pbkdf2_hmac('sha256', old_password.encode('utf-8'), PWD_HASH_SALT, PWD_HASH_ITERATIONS))
        if user.password == hash_old_password:
            user.password = base64.b64encode(hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), PWD_HASH_SALT, PWD_HASH_ITERATIONS))
        self.dao.update(user)
        return user

    def delete(self, uid):
        self.dao.delete(uid)
        return ''

    def get_hash(self, password):
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )
        return base64.b64encode(digest)


