import os
import sys
from dotenv import load_dotenv
load_dotenv()

from app.app.models.user import User
from app.app.models.role import Role
from app.app.schemas.userSchema import UserCreate, UserUpdate
from app.app.db.get_db import get_db
from app.app.crud.baseRepository import BaseRepository
from app.app.config.security.passwordConfiguration import PasswordConfiguration
from typing import List, Dict, Any, Union

from sqlalchemy.orm import Session


passwordConfiguration = PasswordConfiguration()

class UserRepository(BaseRepository[User, UserCreate, UserUpdate]):

    def getUserByEmail(self, db: Session, *, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    def getUserByUsername(self, db: Session, *, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == user).first()

    def create(self, db: Session, *, user_data: UserCreate) -> User:
        user = User(
            email=user_data.getEmail(),
            hashed_password=passwordConfiguration.get_password_hash(user_data.getPassword()),
            full_name=user_data.getFullName(),
            is_active=user_data.getIsActive(),
            is_admin=user_data.getIsAdmin(),
            name=user_data.getName(),
        )
        role = Role(name=user_data.getRole())
        user.roles.append(role)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def update(self, db: Session, *, user_data: User, user_update_data: Union[UserUpdate, Dict[str, Any]]) -> User:
        if isinstance(user_update_data, dict):
            update_data = user_data
        else:
            update_data = user_data.dict(exclude_unset=True)
        if update_data["password"]:
            hashed_password = passwordConfiguration.get_password_hash(update_data["password"])
            del update_data["password"]
            update_data["hashed_password"] = hashed_password
        return super().update(db, db_data=user_data, obj_model=update_data)

    def authenticate(self, db: Session, *, email: str, password: str) -> Optional[User]:
        user = self.getUserByEmail(db, email=email)
        if not user:
            return None
        if not passwordConfiguration.verify_password(password, user.hashed_password):
            return None
        return user

    def is_active(self, user: User) -> bool:
        return user.is_active

    def is_admin(self, user: User) -> bool:
        return user.is_superuser

userRepository = UserRepository(User)
