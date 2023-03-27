import os
import sys
path = os.environ["FILE_PATH"]
sys.path.append(path)

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"])

class PasswordConfiguration:

    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def get_hashed_password(password: str) -> str:
        return pwd_context.hash(password)

