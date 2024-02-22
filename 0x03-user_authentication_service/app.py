#!/usr/bin/env python3
"""
Basic flask app
"""
from flask import Flask, jsonify, request, abort, redirect
from http import HTTPStatus
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def hello_world() -> str:
    """Base route for authentication service API"""
    msg = {"message": "Bienvenue"}
    return jsonify(msg)


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """Registers a new user if it does not exist before"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
    except KeyError:
        abort(HTTPStatus.BAD_REQUEST)

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), \
                HTTPStatus.BAD_REQUEST

    msg = {"email": email, "message": "user created"}
    return jsonify(msg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
