from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNPrinter
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
    ## List all printers with all available information.

    Output information are e.g. cn, dn, members, etc...

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


    if who.role in ["schooladministrator", "globaladministrator"]:
        return lr.get('/printers', school=who.school)
    else:
        printers = []
        for printer in lr.get('/printers', school=who.school):
            if not printer['sophomorixHidden'] or who.dn in printer['member']:
                printers.append(printer)

        return printers

@router.get("/{printer}", name="Get details of a specific printer")
def get_printer(printer: str, all_members: bool = False, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available information of a specific printer.

    Output information are e.g. cn, dn, members, etc...
    The optional query parameter `all_members` is a boolean. If set to true, this endpoint will search recursively for
    all members in all nested groups (may take a while).

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
    printer_details = get_printer_or_404(printer, who.school)

    if all_members:
        printer_details.get_all_members()

    printer_details = printer_details.as_dict()

    if all_members:
        members_list = ",".join(printer_details['all_members'])
        printer_details['members'] = lr.get(f'/batch_users/{members_list}') if members_list else []

    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return printer_details

    elif who.role == "teacher":
        if who.user in printer_details['sophomorixMembers']:
            return printer_details
        elif not printer_details['sophomorixHidden']:
            return printer_details
        else:
            # Maybe the user is member of a group contained in the member attribute of the printer
            memberof = lr.getval(f'/users/{who.user}', 'memberOf')
            for dn in printer_details['member']:
                if dn in memberof:
                    return printer_details
        raise HTTPException(status_code=403, detail=f"Forbidden")

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

    PrinterWriter = LMNPrinter(printer.lower(), school=who.school)
    PrinterWriter.setattr(data=to_change)

    return

@router.post("/{printer}/join", name="Join an existing printer group")
def join_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Join an existing printer group

    This endpoint let the authenticated user join an existing printer group, where *printer* is the cn of this
    printer.

    ### Access
    - teachers

    \f
    :param printer: cn of the printer to join
    :type schoolclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    printer_data = get_printer_or_404(printer, who.school)

    member = False
    if who.dn in printer_data.member:
        member = True
    else:
        # Maybe the user is member of a group contained in the member attribute of the printer
        memberof = lr.getval(f'/users/{who.user}', 'memberOf')
        for dn in printer_data.member:
            if dn in memberof:
                member = True

    if member:
        return f"Already member of the group of {printer}"

    if not printer_data.sophomorixJoinable:
        raise HTTPException(status_code=403, detail=f"Printer {printer} is not joinable.")

    printer_writer = LMNPrinter(printer)
    printer_writer.add_member(who.user)

    return ''

@router.post("/{printer}/quit", name="Quit an existing printer group")
def quit_printer(printer: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Quit an existing printer group

    This endpoint let the authenticated user quit an existing printer group, where *printer* is the cn of this
    printer.

    ### Access
    - teachers

    \f
    :param printer: cn of the printer to quit
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    printer_data = get_printer_or_404(printer, who.school)

    member = False
    if who.dn in printer_data.member:
        member = True
    else:
        # Maybe the user is member of a group contained in the member attribute of the printer
        memberof = lr.getval(f'/users/{who.user}', 'memberOf')
        for dn in printer_data.member:
            if dn in memberof:
                member = True

    if not member:
        return f"Already not a member of the group of {printer}"

    if not printer_data.sophomorixJoinable:
        raise HTTPException(status_code=403, detail=f"Printer {printer} is not joinable and cannot be quitted.")

    printer_writer = LMNPrinter(printer)
    printer_writer.remove_member(who.user)

    return ''