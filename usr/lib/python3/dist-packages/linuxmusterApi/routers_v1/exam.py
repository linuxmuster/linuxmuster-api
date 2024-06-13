from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from security import UserListChecker, AuthenticatedUser
from sophomorix import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/exammode",
    tags=["Exam mode"],
    responses={404: {"description": "Not found"}},
)

class UserList(BaseModel):
    users: list | None = None

@router.post("/start")
def start_exam_mode(userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    Accessible by global-administrators, school-administrators and teachers.
    Use sophomorix.
    """

    if not userlist.users:
        # Nothing to do
        return

    try:
        sophomorixCommand = [
            'sophomorix-exam-mode',
            '--set',
            '--supervisor', who.user,
            '-j',
            '--participants', ','.join(userlist.users)
        ]
        lmn_getSophomorixValue(sophomorixCommand, 'COMMENT_EN')
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting exam mode: {str(e)}")


