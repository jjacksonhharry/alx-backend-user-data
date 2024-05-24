#!/usr/bin/env python3
"""
create a class to manage the API authentication
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """
    Class to manage the API authentication.

    This class provides methods for managing API authentication,
    such asvchecking authorization headers and validating user
    credentials.
    """

    def __init__(self):
        """
        Initializes the Auth class.
        """
        pass

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determine if authentication is required """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True

        # Ensure path ends with a slash for comparison
        if not path.endswith('/'):
            path += '/'

        # Check if the normalized path is in excluded_paths
        for excluded_path in excluded_paths:
            if excluded_path.endswith('/') and path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Get the authorization header from the request """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Get the current user """
        return None
