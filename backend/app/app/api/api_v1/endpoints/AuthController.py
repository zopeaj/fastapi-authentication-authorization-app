import os
import sys
from dotenv import load_dotenv
load_dotenv()

path = os.environ["FILE_PATH"]
sys.path.append(path)

from datetime import timedelta
from fastapi import APIRouter, Depends, Body, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm, OAuth2PasswordRequestFormStrict
from app.app.schemas.authSchema import Login, Token
from app.app.schemas.userSchema import UserSchema, UserUpdate, UserOut
from app.app.schemas.msgSchema import Msg
from app.app.models.user import User
from app.app.core.abstracts.UserService import UserService
from app.app.core.concretes.AuthManager import AuthManager
from app.app.core.concretes.EmailSenderService import EmailSenderService
from app.app.db.get_db import get_db
from sqlalchemy.orm import Session
from app.app.config.security.jwt.jwtConfig import JwtConfig
from app.app.config.security.passwordConfiguration import PasswordConfiguration
from app.app.settings.settingConfiguration import settings

userService = UserService()
emailSenderService = EmailSenderService()
passwordConfig = PasswordConfiguration()
authManager = AuthManager()
jwtConfig = JwtConfig()
securityConfiguration = SecurityConfiguration()


router = APIRouter()
httpBasic = HTTPBasic()


@router.post("/signup", summary="Create new user", response_model=UserOut)
async def sigup(db: Session = Depends(get_db), data: UserAuth):
    # querying database to check if user already exist
    user = userService.getUserByEmail(data.getEmail(db, data.getEmail()))
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    user = {
        "email": data.getEmail(),
        "password": passwordConfig.get_hashed_password(data.getPassword()),
        "id": str(uuid4())
    }
    userOut = UserOut(data.getId())
    userService.create(user)
    return userOut

@router.post("/login", summary="Create access and refresh tokesn for user", response_model=TokenAuth)
async def login(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = userService.getUserByEmail(db, form_data.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    hashed_password = user.getPassword()
    if not passwordConfig.verify_password(form_data.password, hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    return {
        "access_token": securityConfiguration.create_access_token(user.getEmail()),
        "refresh_token": securityConfiguration.create_refresh_token(user.getEmail()),
    }
@app.get("/me", summary="Get details of currently logged in user", response_model=UserOut)
async def get_me(user: User = Depends(securityConfiguration.get_current_user)):
    return user

@router.post("/login/basic-auth", response_model=Login)
def login(credentials: HTTPBasicCredentials = Depends(httpBasic)):
    return {"username": credentials.username, "password": credentials.password}

@router.post("/register", response_model=Register)
def register(*, db: Session = Depends(get_db), user_in: UserCreate, current_user: User = Depends(securityConfiguration.get_current_active_admin)) -> Any:
    """
    Register new user.
    """
    user = userService.getUserByEmail(db, email=user_in.getEmail())
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system. ",
        )
    user = userService.create(db, obj_in=user_in)
    if settings.EMAILS_ENABLED and user.getEmail():
        emailSenderService.send_new_account_email(email_to=user_in.getEmail(), username=user_in.getEmail(), password=user_in.getPassword())
    return user


@router.post("/login", response_model=Token)
def loginUser(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()) -> Any:
    """
    get an access token for future request
    """
    user = authManager.authenticate(db, email=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not authManager.userIsActive(db, user=user):
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token = jwtConfig.generate_token({}, user)
    return {"access_token": access_token} # "token_type": "bearer"

@router.post("/login/test-token", response_model=UserSchema)
def test_token(current_user: User = Depends(securityConfiguration.get_current_user)) -> Any:
    """
    Test access token
    """
    return current_user

@router.post("/password-recovery/{email}", response_model=Msg)
def recover_password(email: str, db: Session = Depends(get_db)) -> Any:
    """
    Password Recovery
    """
    user = UserService.getUserByEmail(db, email=email)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this username does not exist in the system."
        )
    password_reset_token = jwtConfig.generate_password_reset_token(email=email)
    emailSenderService.send_reset_password_email(email_to=user.getEmail(), email=email, token=password_reset_token)
    return {"msg": "Password recovery email sent"}

@router.post("/reset-password/", response_model=Msg)
def reset_password(token: str = Body(...), new_password: str = Body(...), db: Session = Depends(get_db),) -> Any:
    """
    Reset Password
    """
    email = jwtConfig.verify_password_reset_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = userService.getUserByEmail(db, email=email)
    if not user:
        raise HTTPException(
            status_code=404, detail="The user with this username does not exist in the system."
        )
    elif not authManager.userIsActive(user):
        raise HTTPException(status_code=400, detail="Inactive user")

    hashed_password = passwordConfig.get_hashed_password(new_password)
    user_data = UserCreate(**user)
    user_data.setPassword(hashed_password)
    userService.save(db, user, user_data)
    return {"msg": "Password updated successfully"}


