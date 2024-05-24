#!/usr/bin/env python3
"""
class BasicAuth that inherits from Auth
"""
import base64
from api.v1.auth.auth import Auth
from models.user import User
from typing import Optional, TypeVar


class BasicAuth(Auth):
    """
    BasicAuth class that provides Basic Authentication methods.

    This class inherits from Auth and provides methods to handle
    Basic Authentication headers.
    """

    def __init__(self):
        """
        Initializes the Auth class.
        """
        pass

    def extract_base64_authorization_header(self,
                                            authorization_header: str
                                            ) -> Optional[str]:
        """
        Extracts the Base64 part of the Authorization header
        for Basic Authentication.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 part of the Authorization header,
            or None if invalid.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> Optional[str]:
        """
        Decodes the Base64 string and returns the decoded value as
        a UTF-8 string.

        Args:
            base64_authorization_header (str): The Base64 string to decode.

        Returns:
            str: The decoded value as a UTF-8 string, or None if invalid.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """
        Extracts the user email and password from the Base64 decoded value.

        Args:
            decoded_base64_authorization_header (str): The decoded
            Base64 authorization header.

        Returns:
            tuple: A tuple containing the user email and password.
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":", 1)

        return email, password

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str
                                     ) -> Optional[User]:
        """
        Returns the User instance based on email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User: The User instance if found and password matches, else None.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        users = User.search({"email": user_email})
        if not users:
            return None
        user = users[0]
        if user.is_valid_password(user_pwd):
            return user
        return None

    def current_user(self, request=None) -> Optional[User]:
        """
        Retrieves the User instance for a request.

        Args:
            request (str): The request object.

        Returns:
            User: The User instance if authenticated, else None.
        """
        if request is None:
            return None
        auth_header = request.headers.get('Authorization')
        base64 = self.extract_base64_authorization_header(auth_header)
        decoded = self.decode_base64_authorization_header(base64_auth_header)
        email, password = self.extract_user_credentials(decoded_auth_header)
        return self.user_object_from_credentials(email, password)
