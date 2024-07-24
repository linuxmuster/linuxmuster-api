"""
The purpose of this file is to gather all classes used as model for post data.
"""

from pydantic import BaseModel, Field

class UserList(BaseModel):
    """
    A list of samaccountname from users, for starting a project, add to wifi group, etc ...
    """

    users: list | None = None

class LMNShareQuota(BaseModel):
    """
    Model for quotas of shares.
    """

    comment: str | None = '---'
    quota: int
    share: str

class NewProject(BaseModel):
    """
    Model to create a new project.
    """

    admins: list = []
    admingroups: list = []
    description: str | None = ''
    join: bool = True
    hide: bool = False
    mailalias: bool = False
    maillist: bool = False
    mailquota: int | None = None
    members: list = []
    membergroups: list = []
    proxyAddresses: list | None = []
    quota: list[LMNShareQuota] | None = []
    school: str = 'default-school'

class SetFirstPassword(BaseModel):
    """
    Wenn setting the first password, the set_current boolean flag indicates if the current password must be overwritten
    too.
    """

    password: str
    set_current: bool = Field(default= False)

class SetCurrentPassword(BaseModel):
    """
    Wenn setting the current password, the set_first boolean flag indicates if the first password must be overwritten
    too.
    """

    password: str
    set_first: bool= Field(default= False)

class StopExam(BaseModel):
    """
    users is a list of samaccountname from whom stop the exam. The attribute group_type (like "schoolclass") and
    group_name (like "8a") are used to build the path name of the directory which will contain the collected files.
    """

    users: list | None = None
    group_type: str | None = None
    group_name: str | None = None