#!/usr/bin/env python3
""" Returns a salted, hashed password as bytes """
import bcrypt


def hash_user_password(plain_password: str) -> bytes:
    """ Returns a byte string of the hashed password """
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())


def is_password_valid(stored_hashed_password: bytes, input_password: str) -> bool:
    """ Validates the provided password against the stored hashed password """
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password)
