from fastapi import APIRouter, Depends, HTTPException, Request
from time import localtime, strftime

from security import UserListChecker, AuthenticatedUser, RoleChecker
from .body_schemas import UserList, StopExam
from utils.sophomorix import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/exammode",
    tags=["Exam mode"],
    responses={404: {"description": "Not found"}},
)

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
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to handle")

    try:
        # Since the cn of the users are given and uniq across schools, no need to specify the school
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
    :param stopexam: StopExam object containing the list of users, the group type and group name
    :type userlist: StopExam
    :return: Session details
    :rtype: dict
    """


    if not stopexam.users:
        # Nothing to do
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to handle")

    now = strftime("%Y-%m-%d_%Hh%Mm%S", localtime())
    target = f'EXAM_{stopexam.group_type}_{stopexam.group_name}_{now}'

    try:
        # Since the cn of the users are given and uniq across schools, no need to specify the school
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

@router.get("/users", name="List all users in exammode")
def users_exam_mode(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all users in exam mode from the authenticated user (all users in exam mode for admins).

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users in exam mode from the authenticated user (all users in exam mode for admins)
    :rtype: list
    """


    if who.role in ['schooladministrator', 'globaladministrator']:
        return lr.get('/users/exam', school=who.school)
    else:
        return [user for user in lr.get('/users/exam') if user['examTeacher'] == who.user]

@router.get("/users/{user}", name="Get details from an user in exammode")
def user_exam_mode(user: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get details from an user in exam mode. If the caller is not an admin and not the exam teacher, the response
    is then empty. The suffix "-exam" can be omitted and will be automatically added if the given cn is from
    an user which is in exam mode. If the given cn is not from an user in exam mode, the response will be empty.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param user: cn of the user
    :rtype user: basestring
    :return: Details of user in exam mode
    :rtype: dict
    """


    data = lr.get(f'/users/exam/{user}', school=who.school)

    if not data:
        return {}

    if who.role in ['schooladministrator', 'globaladministrator']:
        return data
    else:
        if data['examTeacher'] == who.user:
            return data

    return {}
