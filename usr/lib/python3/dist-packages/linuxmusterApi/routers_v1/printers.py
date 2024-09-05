from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from utils.checks import get_printer_or_404
from utils.sophomorix import lmn_getSophomorixValue
from .body_schemas import Printer


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

@router.patch("/{printer}", status_code=204, name="Patch printer")
def patch_printer(printer: str, printer_details: Printer, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Update the parameters of a specific printer

    *printer_details* are the attribute of the printer, like *description*,
    *join* if the printer should be joinable, *hide*, etc ... and can be partial.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param printer: The printer to modify
    :type printer: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    printer_exists = get_printer_or_404(printer, who.school)

    # for option in ['addmembers', 'removemembers', 'addmembergroups', 'removemembergroups']:
    #     if getattr(printer_details, option):

    printer_member = printer_exists.member
    members_changed = False

    for user in printer_details.addmembers:
        user_dn = lr.getval(f'/users/{user}', 'distinguishedName')
        if user_dn not in printer_member:
            printer_member.append(user_dn)
            members_changed = True

    for user in printer_details.removemembers:
        user_dn = lr.getval(f'/users/{user}', 'distinguishedName')
        if user_dn in printer_member:
            printer_member.remove(user_dn)
            members_changed = True

    for group in printer_details.addmembergroups:
        group_dn = lr.getval(f'/units/{group}', 'distinguishedName')
        if group_dn not in printer_member:
            printer_member.append(group_dn)
            members_changed = True

    for group in printer_details.removemembergroups:
        group_dn = lr.getval(f'/units/{group}', 'distinguishedName')
        if group_dn in printer_member:
            printer_member.remove(group_dn)
            members_changed = True

    if members_changed:
        to_change = {'member': printer_member}
    else:
        to_change = {}

    if printer_details.description:
        to_change['description'] = printer_details.description

    if printer_details.join:
        to_change['sophomorixJoinable'] = "TRUE"
    else:
        to_change['sophomorixJoinable'] = "FALSE"

    if printer_details.hide:
        to_change['sophomorixHidden'] = "TRUE"
    else:
        to_change['sophomorixHidden'] = "FALSE"

    if printer_details.school:
        to_change['sophomorixSchoolname'] = printer_details.school

    if printer_details.displayName:
        to_change['displayName'] = printer_details.displayName

    lw.set(printer.lower(), 'printer', to_change)

    return

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