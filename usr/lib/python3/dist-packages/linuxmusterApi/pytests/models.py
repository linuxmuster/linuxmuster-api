from base64 import b64encode
from .jwtapi import jwt_get
from pydantic import BaseModel, computed_field


class LMNTestUser(BaseModel):
    cn: str
    password: str
    role: str
    school: str

    @computed_field
    @property
    def basic_token(self) -> str:
        return b64encode(f"{self.cn}:{self.password}".encode('utf-8')).decode("ascii")

    @computed_field
    @property
    def wrongbasic_token(self) -> str:
        return b64encode(f"{self.cn}:{self.password[:-1]}".encode('utf-8')).decode("ascii")

    @computed_field
    @property
    def jwt(self) -> str:
        return jwt_get(self.cn)

    @computed_field
    @property
    def wrongjwt(self) -> str:
        return jwt_get(self.cn).replace('e', 'E').replace('w', 'a')