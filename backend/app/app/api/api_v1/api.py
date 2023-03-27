import os
import sys
from dotenv import load_dotenv
load_dotenv()

path = os.environ["FILE_PATH"]
sys.path.append(path)

from fastapi import APIRouter

from app.app.api.api_v1.endpoints import UserController, AuthController


api_router = APIRouter()
api_router.include_router(AuthController.router, prefix="/auth", tags=["login"])
api_router.include_router(UserController.router, prefix="/users", tags=["users"])
