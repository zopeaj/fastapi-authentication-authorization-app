import os
import sys
path = os.environ["FILE_PATH"]
sys.path.append(path)
import secrets
from fastapi.security import (HTTPBasic, HTTPBasicCredentials,
OAuth2PasswordBearer, OAuth2PasswordRequestFormStrict, OAuth2PasswordRequestForm)
from app.app.config.security.jwt.jwtConfig import JwtConfig
from app.app.core.abstracts.UserService import UserService
from app.app.core.concretes.AuthManager import AuthManager
from app.app.schemas.authSchema import TokenPayload
from app.app.models.user import User, SystemUser
from app.app.settings.settingConfiguration import settings
from app.app.db.get_db import get_db
from fastapi import Depends, HTTPException, status
from typing import Optional
from datetime import timedelta, datetime
from sqlalchemy.orm import Session
from jose import jwt
from pydantic import ValidationError


httpBasic = HTTPBasic()
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token", scheme_name="JWT")
jwtConfig = JwtConfig()
userService = UserService()
authManager = AuthManager()

class SecurityConfiguration:

    def get_current_username(credentials: HTTPBasicCredentials = Depends(httpBasic)):
        correct_username = credentials.username
        correct_password = credentials.password
        # correct_username = secrets.compare_digest(credentials.username, "stanleyjobson")
        # correct_password = secrets.compare_digest(credentials.password, "swordfish")
        if not (correct_username and correct_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username

    def get_current_user(db: Session = Depends(get_db), token: str = Depends(reusable_oauth2)) -> User:
        token_data = self.decode_token_for_current_user(token)
        user = userService.getUserByUsername(db, username=token_data.getSub())
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user

    def decode_token_for_current_user(token: str) -> Optional[TokenPayload]:
        try:
            payload = jwt.decode(
                token, jwtConfig.get_secret_key(), algorithms=[jwtConfig.get_algorithm()]
            )
            token_data = TokenPayload(**payload)

            if datetime.fromtimestamp(token.getExp()) < datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except (jwt.JWTError, ValidationError):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = userService.getUserByUsername(token_data.getSub())

        if user is None:
            raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Could not find user",
                )
        return SystemUser(**user)

    def get_current_active_user(current_user: User = Depends(self.get_current_user)) -> User:
        user_is_active = authManager.userIsActive(current_user)
        if not user_is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user

    def get_current_active_admin(current_user: User = Depends(self.get_current_user)) -> User:
        user_is_admin = authManager.userIsAdmin(current_user)
        if not user_is_active:
            raise HTTPException(status_code=400, detail="The user doesn't have enough privileges")
        return current_user



