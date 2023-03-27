from pydantic import BaseModel

class TokenData(BaseModel):
    username: str

    def getUsername(self):
        return self.username

token_data = TokenData(username="Data")
print(token_data.getUsername())
