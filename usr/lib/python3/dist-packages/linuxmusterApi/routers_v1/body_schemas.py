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

class Printer(BaseModel):
    """
    Model to handle a printer group.
    """

    addmembers: list = []
    addmembergroups: list = []
    description: str | None = ''
    displayName: str | None = ''
    join: bool = True
    hide: bool = False
    removemembers: list = []
    removemembergroups: list = []
    school: str = 'default-school'

class Project(BaseModel):
    """
    Model to create a new project.
    """

    admins: list = []
    admingroups: list = []
    description: str | None = ''
    displayName: str | None = ''
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

class User(BaseModel):
    """
    Model to patch user's data.
    """

    givenName: str | None = ''
    displayName: str | None = ''
    mailalias: bool = False
    name: str | None = ''
    proxyAddresses: list | None = []
    sn: str | None = ''
    sophomorixCustom1: str | None = ''
    sophomorixCustom2: str | None = ''
    sophomorixCustom3: str | None = ''
    sophomorixCustom4: str | None = ''
    sophomorixCustom5: str | None = ''
    sophomorixCustomMulti1: list | None = []
    sophomorixCustomMulti2: list | None = []
    sophomorixCustomMulti3: list | None = []
    sophomorixCustomMulti4: list | None = []
    sophomorixCustomMulti5: list | None = []

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

class PrintPasswordsSchoolclassesParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """

    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = False
    school: str | None = ''
    schoolclasses: list

class PrintPasswordsProjectsParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """

    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = False
    school: str | None = ''
    projects: list

class PrintPasswordsUsersParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """

    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = False
    school: str | None = ''
    users: list
