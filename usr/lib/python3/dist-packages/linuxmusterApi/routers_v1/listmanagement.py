import ldap
import logging
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from utils.checks import check_valid_mgmtlist_or_404
from linuxmusterTools.lmnfile import LMNFile
from .body_schemas import MgmtList


router = APIRouter(
    prefix="/listmanagement",
    tags=["List Management"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{mgmtlist}", name="Get the content of a specific management list")
def get_management_list_content(school: str, mgmtlist: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get the content of a management list (file like /etc/linuxmuster/sophomorix/default-school/teachers.csv).
    The school must be extra given, because it's not possible to know which school a global-administrator would like
    to request.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param mgmtlist: A valid role (plural) like 'teachers'
    :type mgmtlist: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    path = check_valid_mgmtlist_or_404(mgmtlist, school)

    try:
        with LMNFile(path, 'r') as list:
            return list.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading {path}: {str(e)}")

@router.post("/{school}/{mgmtlist}", name="Write content of a specific management list")
def post_management_list_content(school: str, mgmtlist: str, content: MgmtList, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Write the content of a management list (file like /etc/linuxmuster/sophomorix/default-school/teachers.csv).
    The school must be extra given, because it's not possible to know which school a global-administrator would like
    to request. This will overwrite the content of the CSV file, but LMNFile automatically makes a backup of the old
    CSV file.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param mgmtlist: A valid role (plural) like 'teachers'
    :type mgmtlist: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param content: Content of the CSV, see MgmtList attributes
    :type content: MgmtList
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    path = check_valid_mgmtlist_or_404(mgmtlist, school)

    try:
        with LMNFile(path, 'w') as list:
            return list.write(content.data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error writing {path}: {str(e)}")
