#!/usr/bin/env python3
"""
Module for authentication using Basic auth
"""

from typing import TypeVar
from api.v1.auth.auth import Auth
import base64
from models.user import User

class BasicAuth(Auth):
    """Class for Basic Authentication"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header."""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[-1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """Decodes the Base64 Authorization header."""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """Extracts user credentials from the decoded Base64 Authorization header."""
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        split_index = decoded_base64_authorization_header.find(':')
        email = decoded_base64_authorization_header[:split_index]
        password = decoded_base64_authorization_header[split_index + 1:]
        return (email, password)

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on email and password."""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            if not users:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current User instance based on request."""
        auth_header = self.authorization_header(request)
        if auth_header is not None:
            token = self.extract_base64_authorization_header(auth_header)
            if token is not None:
                decoded = self.decode_base64_authorization_header(token)
                if decoded is not None:
                    email, password = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(email, password)
        return None
