from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNPrinter
from utils.checks import get_dn_or_404, get_printer_or_404
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


    get_printer_or_404(printer, who.school)

    # Resolve every name before writing anything: those fields are lists, and
    # a partial refusal would let the caller believe the whole patch went
    # through. The writer resolves them again, cheaply, when it applies them.
    for user in printer_details.addmembers + printer_details.removemembers:
        get_dn_or_404('users', user, 'User')

    for group in printer_details.addmembergroups + printer_details.removemembergroups:
        get_dn_or_404('units', group, 'Group')

    members_to_add = printer_details.addmembers + printer_details.addmembergroups
    members_to_remove = printer_details.removemembers + printer_details.removemembergroups

    to_change = {}

    if printer_details.description:
        to_change['description'] = printer_details.description

    # None means "not sent": a partial patch must not rewrite an attribute the
    # caller never mentioned, or a patch adding a member would also unhide the
    # printer and make it joinable, straight from the schema defaults.
    if printer_details.join is not None:
        to_change['sophomorixJoinable'] = "TRUE" if printer_details.join else "FALSE"

    if printer_details.hide is not None:
        to_change['sophomorixHidden'] = "TRUE" if printer_details.hide else "FALSE"

    if printer_details.school:
        to_change['sophomorixSchoolname'] = printer_details.school

    if printer_details.displayName:
        to_change['displayName'] = printer_details.displayName

    PrinterWriter = LMNPrinter(printer.lower(), school=who.school)

    # add_members() and remove_members() each apply one targeted LDAP modify,
    # so two patches landing at the same time cannot overwrite each other.
    failures = []

    if members_to_add:
        failures.extend(PrinterWriter.add_members(members_to_add))

    if members_to_remove:
        failures.extend(PrinterWriter.remove_members(members_to_remove))

    if failures:
        detail = ", ".join(f"{member}: {error}" for member, error in failures)
        raise HTTPException(status_code=500, detail=f"Could not update the members of {printer}: {detail}")

    if to_change:
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

    printer_writer = LMNPrinter(printer, school=who.school)
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

    printer_writer = LMNPrinter(printer, school=who.school)
    printer_writer.remove_member(who.user)

    return ''