#!/usr/bin/env python3
"""
Basic Flask ap
"""
from flask import Flask, jsonify
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def welcome():
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        # Attempt to register the user
        AUTH.register_user(email, password)

        # If successful, respond with a success message
        return jsonify({"email": email, "message": "user created"}), 200

    except Auth.UserAlreadyExistsError:
        # If the user already exists, respond with an error message
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
