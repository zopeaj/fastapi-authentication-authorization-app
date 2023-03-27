import os
import sys
from dotenv import load_dotenv
load_dotenv()

from typing import Optional
from app.app.crud.repository.UserRepository import userRepository
from app.app.models.user import User
from sqlalchemy.orm import Session

class UserService:
    def save(self, db: Session, *, user_data: UserCreate) -> User:
        user_data = self.getUserByEmail(db, user_data.getEmail())
        if not user:
            return True
        user = userRepository.create(db, user_data)
        return user

    def updateUser(self, db: Session, *, user_data: User, user_update_data: Union[UserUpdate, Dict[str, Any]]) -> User:
        user_data = self.getUserByEmail(user_data.getEmail())
        if not user:
            return True
        user = userRepository.update(db, user_data, user_update_data)
        return user

    def getUserByEmail(self, db: Session, *, email: str) -> Optional[User]:
        user = userRepository.getUserByEmail(db, email)
        if user is not None:
            return user
        return None

    def getUserByUsername(self, db: Session, *, username: str) -> Optional[User]
        user = userRepository.getUserByUsername(db, username)
        if user is not None:
            return user
        return None

    def getMultipleUsers(self, db: Session, *, skip: int = 0, limit: int = 100) -> List[User]:
        users = userRepository.get_multi(db, skip=skip, limit=limit)
        return users
