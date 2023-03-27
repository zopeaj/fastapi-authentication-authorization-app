from typing import Optional

from pydantic import BaseModel

class Role(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
