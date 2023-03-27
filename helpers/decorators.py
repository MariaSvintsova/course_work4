import jwt
from flask import abort, request

from views.auth import secret, algo


def auth_reqiured(func):
    def wrapper(*args, **kwargs):
        """Checking and decode token"""
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]

        try:
            data = jwt.decode(token, secret, algorithms=[algo])
        except Exception as e:
            abort(401)
            return 'JWT decode exception', e

        return func(data=data, *args, **kwargs)
    return wrapper

def admin_required(func):
    def wrapper(*args, **kwargs):
        """Checking, decode token and checking role 'admin' """
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]

        try:
            sl = jwt.decode(token, secret, algorithms=[algo])
            if sl["role"] == 'admin':
                return func(*args, **kwargs)
            else:
                abort(403)
                return 'Allowed only for admins'
        except Exception as e:
            abort(401)
            return 'JWT decode exception', e
    return wrapper
