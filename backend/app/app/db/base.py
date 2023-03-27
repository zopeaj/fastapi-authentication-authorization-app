import os
import sys
from dotenv import load_dotenv
load_dotenv()
path = os.environ["FILE_PATH"]
sys.path.append(path)

from app.app.db.base_class import Base
from app.app.models.role import Role
from app.app.models.user import User
from app.app.db.session import engine
