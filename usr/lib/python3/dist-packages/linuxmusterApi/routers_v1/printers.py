from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.checks import get_printer_or_404
from utils.sophomorix import lmn_getSophomorixValue


router = APIRouter(
    prefix="/printers",
    tags=["Printers"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all printers")
def get_all_printers(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all printers with all available informations.

    Output informations are e.g. cn, dn, members, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all printers details (dict)
    :rtype: list
    """


    return lr.get('/printers')

@router.get("/{printer}", name="Get details of a specific printer")
def get_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available informations of a specific schooclass.

    Output informations are e.g. cn, dn, members, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param printer: cn of the requested printer
    :type printer: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all printers details (dict)
    :rtype: list
    """


    # TODO: Check group membership
    get_printer_or_404(printer, who.school)

    printer = lr.get(f'/printers/{printer}')
    printer['members'] = [lr.get(f'/users/{member}') for member in printer['sophomorixMembers']]

    return printer

@router.patch("/{printer}", name="TODO")
def patch_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    TODO

    :param printer:
    :type printer:
    :param who:
    :type who:
    :return:
    :rtype:
    """

@router.post("/{printer}/join", name="Join an existing printer group")
def join_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Join an existing printer group

    This endpoint let the authenticated user join an existing printer group, where *printer* is the cn of this
    printer.

    ### Access
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param printer: cn of the printer to join
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """

    get_printer_or_404(printer, who.school)

    cmd = ['sophomorix-group',  '--addmembers', who.user, '--group', printer.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result

@router.post("/{printer}/quit", name="Quit an existing printer group")
def quit_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Quit an existing printer group

    This endpoint let the authenticated user quit an existing printer group, where *printer* is the cn of this
    printer.

    ### Access
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param printer: cn of the printer to quit
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """

    get_printer_or_404(printer, who.school)

    cmd = ['sophomorix-group',  '--removemembers', who.user, '--group', printer.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result