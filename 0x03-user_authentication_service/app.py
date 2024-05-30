#!/usr/bin/env python3
"""
Basic flask app
"""
from flask import Flask, jsonify, request, abort, make_response
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/users", methods=["POST"])
def register_user():
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """
    POST /sessions route to log in a user.
    Expects form data with "email" and "password".
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(401)

    # Validate the user's credentials
    if not AUTH.valid_login(email, password):
        abort(401)

    # Create a new session for the user
    session_id = AUTH.create_session(email)
    if session_id is None:
        abort(401)

    # Create the response
    response = make_response(jsonify({"email": email, "message": "logged in"}))
    response.set_cookie('session_id', session_id)

    return response


@app.route("/")
def index():
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
