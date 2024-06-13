from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from time import localtime, strftime

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

class StopExam(BaseModel):
    users: list | None = None
    group_type: str | None = None
    group_name: str | None = None

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


@router.post("/stop")
def stop_exam_mode(stopexam: StopExam, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    Accessible by global-administrators, school-administrators and teachers.
    Use sophomorix.
    """

    if not stopexam.users:
        # Nothing to do
        return

    now = strftime("%Y-%m-%d_%Hh%Mm%S", localtime())
    target = f'EXAM_{stopexam.group_type}_{stopexam.group_name}_{now}'

    try:
        sophomorixCommand = [
            'sophomorix-exam-mode',
            '--unset',
            '--subdir', f'transfer/collected/{target}',
            '-j',
            '--participants', ','.join(stopexam.users)
        ]
        lmn_getSophomorixValue(sophomorixCommand, 'COMMENT_EN')
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stoping exam mode: {str(e)}")
