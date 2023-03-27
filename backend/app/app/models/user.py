import os
import sys
from dotenv import load_dotenv
load_dotenv()
path = os.environ["FILE_PATH"]
sys.path.append(path)

from app.app.db.base_class import Base
from app.app.models.role import Role
from sqlalchemy import Column, String, Integer, ForeignKey, Sequence, Boolean
from sqlalchemy.orm import relationship, backref
from uuid import uuid4


class User(Base):
    id = Column(Integer, Sequence("user_id_seq"), primary_key=True, default=uuid4)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False)
    is_admin = Column(Boolean, nullable=False)
    name = Column(String, nullable=False)
    roles = relationship("Role", uselist=True, lazy='joined', back_populates="user")
