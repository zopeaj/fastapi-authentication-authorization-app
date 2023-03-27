import os
import sys
from dotenv import load_dotenv
load_dotenv()
path = os.environ["FILE_PATH"]
sys.path.append(path)

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.encoders import jsonable_encoder
from app.app.schemas.userSchema import UserSchema, UserUpdate, UserCreate
from app.app.models.user import User
from app.app.core.abstracts.UserService import UserService
from app.app.config.security.securityConfiguration import SecurityConfiguration
from app.app.config.settings.settingConfiguration import settings
from app.app.core.concretes.AuthManager import AuthManager
from app.app.db.get_db import get_db
from pydantic import EmailStr

router = APIRouter()
httpBasic = HTTPBasic()


securityConfiguration = SecurityConfiguration()
userService = UserService()
authManager = AuthManager()

@router.get("/", response_model=List[UserSchema])
def read_users(db: Session = Depends(get_db), skip: int = 0, limit: int = 100, current_user: User = Depends(securityConfiguration.get_current_active_admin)) -> Any:
    users = userService.getMultipleUsers(db, skip=skip, limit=limit)
    return users

@router.put("/me", response_model=UserSchema)
def update_user_me(*, db: Session = Depends(get_db), password: str = Body(None), full_name: str = Body(None), email: EmailStr = Body(None), current_user: User = Depends(securityConfiguration.get_current_active_user)) -> Any:
    """
    Update own user.
    """
    current_user_data = jsonable_encoder(current_user)
    user_in = UserUpdate(**current_user_data)
    if password is not None:
        user_in.setPassword(password)
    if full_name is not None:
        user_in.setFullName(full_name)
    if email is not None:
        user_in.setEmail(email)
    user = userService.update(db, db_obj=current_user, obj_in=user_in)
    return user


@router.get("/me", response_model=UserSchema)
def read_user_me(db: Session = Depends(get_db), current_user: User = Depends(securityConfiguration.get_current_active_user)) -> Any:
    """
    Get current user.
    """
    return current_user

@router.post("/open", response_model=UserSchema)
def create_user_open(*, db: Session = Depends(get_db), password: str = Body(...), email: EmailStr = Body(...), full_name: str = Body(None),) -> Any:
    """
    Create new user without the need to be logged in.
    """
    if not settings.USERS_OPEN_REGISTRATION:
        raise HTTPException(
            status_code=403,
            detail="Open user registration is forbidden on this server",
        )
    user = userService.getUserByEmail(db, email=email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system",
        )
    user_in = UserCreate(password=password, email=email, full_name=full_name)
    user = userService.create(db, obj_in=user_in)
    return user

@router.get("/{user_id}", response_model=UserSchema)
def read_user_by_id(user_id: int, current_user: User = Depends(securityConfiguration.get_current_active_user), db: Session = Depends(get_db)) -> Any:
    """
    Get a specific user by id.
    """
    user = userService.get(db, id=user_id)
    if user == current_user:
        return user
    if not authManager.userIsActive(current_user):
        raise HTTPException(
            status_code=400, detail="The user doesn't have enough privileges"
        )
    return user

@router.put("/{user_id}", response_model=UserSchema)
def update_user(*, db: Session = Depends(get_db), user_id: int, user_in: UserUpdate, current_user: User = Depends(securityConfiguration.get_current_active_admin)) -> Any:
    """
    Update a user.
    """
    user = userService.get(db, id=user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this username does not exist in the system."
        )
    user = userService.update(db, db_obj=user, obj_in=user_in)
    return user


