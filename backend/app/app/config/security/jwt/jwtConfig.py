import os
import sys
path = os.environ["FILE_PATH"]
sys.path.append(path)

from jose import JWTError, jwt
from app.app.config.settings.settingConfiguration import settings
from app.app.schemas.authSchema import TokenData
from app.app.model.user import User
from pydantic import ValidationError
from fastapi import HTTPException, status, Depends
from typing import List, Union, Any



class JwtConfig:
    def __init__(self):
        self.secret_key:str = "c3c25813e5ca064561912f023760b4e9d98c6fbf9daad38df4bcd1cc27f1de22"
        self.algorithm: str = "HS256"
        self.access_token_expire_minutes: int = 30 # 30 minutes
        self.refresh_token_expire_minutes: int = 60 * 24 * 7 # 7 days
        self.jwt_refresh_secret_key: str = "cf61e8a08e38033a64e1c81d2c003d20b23028fda75de476bcb839b1646b686e"

    def extract_aud(token: dict) -> List[str]:
        return token.get("aud")

    def extract_iss(token: str) -> str:
        return token.get("iss")

    def extract_subject(token: dict) -> str:
        return token.get("sub")

    def extract_email(token: dict) -> str:
        return token.get("sub")

    def generate_token(data: dict, user: User) -> str:
        to_encode = data.copy()
        if settings.ACCESS_TOKEN_EXPIRE_MINUTES:
            expire = datetime.utcnow() + settings.DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        roles = [role.getName() for role in user.getRoles()]
        to_encode.update({"exp": expire, "sub":user.getUsername() or user.getEmail(), "iss": settings.TOKEN_ISSUER, "iat": settings.ISSUED_AT, "aud": roles})
        encoded_jwt = jwt.encode(to_encode, self.get_secret_key(), algorithm=self.get_algorithm())
        return encoded_jwt

    def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
        if expires_delta is not None:
            expires_delta = datetime.utcnow() + expires_delta
        else:
            expires_delta = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes())

        to_encode = {"exp": expires_delta, "sub": str(subject)}
        encoded_jwt = jwt.encode(to_encode, self.get_secret_key(), self.algorithm())
        return encoded_jwt

    def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
        if expires_delta is not None:
            expires_delta = datetime.utcnow() + expires_delta
        else:
            expires_delta = datetime.utcnow() + timedelta(minutes=self.get_refresh_token_expire_minutes())

        to_encode = {"exp": expires_delta, "sub": str(subject)}
        encoded_jwt = jwt.encode(to_encode, self.get_jwt_refresh_secret_key(), self.get_algorithm())
        return encoded_jwt

    def decode_token(token: str, user: User) -> TokenData:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentails",
            headers={"WWW-Authenticate": "Bearer"},
        )
        roles: List[str] = [role.getName() for role in user.getRoles()]
        token_data = None
        try:
            payload = jwt.decode(token, self.get_secret_key(), issuer=settings.TOKEN_ISSUER, audience=roles, algorithms=[self.get_algorithm()], options=["require": ["exp", "sub", "iss", "iat", "aud"]])
            username = self.extract_subject(payload)
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
            return token_data
        except JWTError:
            raise credentials_exception

    def generate_reset_token(email: str) -> str:
        delta = timedelta(hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS)
        now = datetime.utcnow()
        expires = now + delta
        exp = expires.timestamp()
        encoded_jwt = jwt.encode({"exp": exp, "nbf": now, "sub": email}, self.get_secret_key(), algorithm=self.get_algorithm())

    def verify_reset_token(token: str) -> Optional[str]:
        try:
            decoded_token = jwt.decode(token, self.get_secret_key(), algorithms=[self.get_algorithm()])
            return extract_email(decoded_token)
        except JWTError:
            return None

    def generate_password_reset_token(email: str) -> str:
        encoded_jwt = self.generate_reset_token(email)
        return encoded_jwt

    def verify_password_reset_token(token: str) -> Optional[str]:
        email = self.verify_reset_token(token)
        return email

    def get_secret_key(self) -> str:
        return self.secret_key or settings.SECRET_KEY

    def get_algorithm(self) -> str:
        return self.algorithm

    def get_access_token(self) -> int:
        return self.access_token_expire_minutes

    def get_refresh_token_expire_minutes(self) -> int:
        return self.refresh_token_expire_minutes

    def get_jwt_refresh_secret_key(self) -> str:
        return self.jwt_refresh_secret_key
