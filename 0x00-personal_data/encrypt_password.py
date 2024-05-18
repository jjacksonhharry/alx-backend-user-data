#!/usr/bin/env python3
"""
function that expects one string argument
name password and returns a salted,
hashed password, which is a byte string
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt.

    :param password: The password to hash.
    :return: The salted, hashed password as a byte string.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate a password against a hashed password using bcrypt.

    :param hashed_password: The hashed password.
    :param password: The password to validate.
    :return: True if the password matches the hashed password, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
