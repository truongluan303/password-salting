import hashlib
from typing import Optional
import os
import re




class Account:
    """
    An example of account class
    """
    def __init__(self, username, password):
        self.username = username
        self.password = PasswordManager.encrypt_password(password)
        
        



class PasswordManager:

    BYTE_LENGTH = 32

    ITERATIONS = 100000

    HASH = 'sha256'



    @staticmethod
    def encrypt_password(password: str) -> bytes:
        """
        Encrypt a password into an undecryptable string
        Args:
            password (str): the password to be encrypted
        Returns:
            str: the encrypted version of the password
        """
        salt = os.urandom(PasswordManager.BYTE_LENGTH)
        
        encoded = password.encode()
        
        key = hashlib.pbkdf2_hmac(PasswordManager.HASH, encoded, salt,
                                  PasswordManager.ITERATIONS)
        
        storage = salt + key
        
        return storage




    @staticmethod
    def check_password(account: Optional[Account], entered_password: str) -> bool:
        """
        Check if a password entered by the user for an account is correct
        Args:
            account (Optional[Account]): the account to check the password for
            entered_password (str): the password entered by the user
        Returns:
            bool: true if the entered password is correct
        """
        salt = account.password[:PasswordManager.BYTE_LENGTH]
        key = account.password[PasswordManager.BYTE_LENGTH:]
        
        encoded = entered_password.encode()
        
        new_key = hashlib.pbkdf2_hmac(PasswordManager.HASH, encoded, salt,
                                      PasswordManager.ITERATIONS)
        
        return new_key == key




    @staticmethod
    def is_valid_password(password: str) -> bool:
        """
        Check if a string can be used as a password. The given string must be at least
        8 characters, and must contain a lower case letter, an upper case letter, a number,
        and a special character
        Args:
            password (str): the password to be checked against
        Returns:
            bool: true if the given password pass the test
        """
        reg = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return bool(re.match(reg, password))
