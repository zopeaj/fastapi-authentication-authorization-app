import os
import sys
path = os.environ["FILE_PATH"]
sys.path.append(path)

from app.app.db.base import User

