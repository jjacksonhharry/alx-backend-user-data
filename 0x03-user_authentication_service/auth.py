#!/usr/bin/env python3
"""
method that takes in a password string
arguments and returns bytes
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hash a password with bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the input password.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the generated salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password
