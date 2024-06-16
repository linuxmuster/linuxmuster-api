from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from time import localtime, strftime

from security import UserListChecker, AuthenticatedUser
from utils.sophomorix import lmn_getSophomorixValue
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

@router.post("/start", name="Start exam")
def start_exam_mode(userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Start exam for the authenticated user

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param userlist: List of samaccountname for whom start the exam
    :type userlist: UserList
    :return: Session details
    :rtype: dict
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


@router.post("/stop", name="Stop exam")
def stop_exam_mode(stopexam: StopExam, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Stop exam of the authenticated user

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param userlist: List of samaccountname for whom stop the exam
    :type userlist: UserList
    :return: Session details
    :rtype: dict
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
