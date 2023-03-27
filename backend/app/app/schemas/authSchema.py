from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field


class Login(BaseModel):
    username: str
    password: Any

class Token(BaseModel):
    refresh_token: str
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

    def getUsername(self):
        return self.username

class TokenPayload(BaseModel):
    sub: Optional[str] = None

    def getSub(self) -> Optional[str]:
        return self.sub

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str

class TokenPayload(BaseModel):
    sub: str = None
    exp: int = None

    def getSub(self) -> str:
        return self.sub

    def getExp(self) -> str:
        return self.exp

class UserAuth(BaseModel):
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")
