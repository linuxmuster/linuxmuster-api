"""
The purpose of this file is to gather all classes used as model for post data.
"""

from pydantic import BaseModel, Field

class UserList(BaseModel):
    """
    A list of samaccountname from users, for starting a project, add to wifi group, etc ...
    """

    users: list | None = None

class NewProject(BaseModel):
    """
    Model to create a new project.
    """

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