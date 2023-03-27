import os
import sys
from dotenv import load_dotenv
load_dotenv()
path = os.environ["FILE_PATH"]
sys.path.append(path)

from app.app.db.base_class import Base
from sqlalchemy import Column, String, Integer, ForeignKey, Sequence
from uuid import uuid4


class Role(Base):
    id = Column(Integer, Sequence("role_id_seq"), primary_key=True, default=uuid4)
    name = Column(String, nullable=False)
    user_id = Column(ForeignKey("user.id"), primary_key=True)
