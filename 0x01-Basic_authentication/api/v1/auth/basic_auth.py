#!/usr/bin/env python3
"""
class BasicAuth that inherits from Auth
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """
    Basic Authentication class that inherits from Auth
    """

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
