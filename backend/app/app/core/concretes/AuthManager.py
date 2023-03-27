import os
import sys
from dotenv import load_dotenv
load_dotenv()

from app.app.crud.repository.UserRepository import userRepository
from sqlalchemy.orm import Session
from app.app.models.user import User


class AuthManager:
    def authenticate(self, db: Session, *, email: str, password: str) -> Optional[User]:
        user = userRepository.authenticate(db, email, password)
        if not user:
            return False
        return True

    def userIsActive(self, db: Session, *, user: User) -> bool:
        pass

    def userIsAdmin(self, db: Session, *, user: User) -> bool:
        pass

    # def authenticate_user(fake_db, username: str, password: str):
    #     pass
