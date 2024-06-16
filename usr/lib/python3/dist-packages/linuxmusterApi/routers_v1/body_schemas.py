from pydantic import BaseModel, Field

class UserList(BaseModel):
    users: list | None = None

class NewProject(BaseModel):
    description: str | None = ''
    quota: str = ''
    mailquota: str = ''
    join: bool = True
    hide: bool = False
    admins: list = []
    admingroups: list = []
    members: list = []
    membergroups: list = []
    school: str = 'default-school'

class SetFirstPassword(BaseModel):
    password: str
    set_current: bool = Field(default= False)

class SetCurrentPassword(BaseModel):
    password: str
    set_first: bool= Field(default= False)

class StopExam(BaseModel):
    users: list | None = None
    group_type: str | None = None
    group_name: str | None = None