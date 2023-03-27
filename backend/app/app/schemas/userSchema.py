from typing import List, Optional
from pydantic import BaseModel, EmailStr
from uuid import UUID

# Shared properties
class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = False
    is_admin: bool = False
    full_name: Optional[str] = None
    name: Optional[str] = None
    roles: Optional[List[Role]] = None

# Properties to receive via API on creation
class UserCreate(UserBase):
    email: EmailStr
    password: str
    is_admin: bool
    is_active: bool
    full_name: str
    name: str
    roles: List[Role]

# Properties to receive via API on update
class UserUpdate(UserBase):
    password: Optional[str] = None

class UserInDBBase(UserBase):
    id: Optional[int] = None

    class Config:
        orm_mode = True


# Additional properties to return via API
class UserSchema(UserInDBBase):
    pass

# Additional properties stored in DB
class UserInDB(UserInDBBase):
    hashed_password: str



class UserOut(BaseModel):
    id: UUID
    email: str

class SystemUser(UserOut):
    password: str

