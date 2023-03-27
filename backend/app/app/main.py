import os
import sys
from dotenv import load_dotenv
load_dotenv()
path = os.environ["FILE_PATH"]
sys.path.append(path)

# name = os.getenv("MY_NAME")
# print(f"Hello {name} from python")
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from app.app.api.api_v1.api import api_router
from app.app.config.settings.settingConfiguration import settings
from app.app.db.base import Base
from app.app.db.base import engine

Base.metadata.create_all(engine)

app = FastAPI(title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json")

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix=settings.API_V1_STR)


