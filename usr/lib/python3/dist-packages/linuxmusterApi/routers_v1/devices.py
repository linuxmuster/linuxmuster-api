import configparser
import os
import subprocess
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNDevice
from linuxmusterTools.lmnconfig import SophomorixIni
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.samba_util import DeviceManager
from utils.checks import get_printer_or_404
from utils.sophomorix import lmn_getSophomorixValue
from .body_schemas import MgmtList, Device
from utils.checks import check_valid_school_or_404, require_school

router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
    responses={404: {"description": "Not found"}},
)

@router.get("/list/{school}", name="List all devices")
@require_school
def get_all_devices(school: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all devices from devices.csv with all available information.

    Output information are e.g. cn, dn, etc...

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all devices details (dict)
    :rtype: list
    """


    if school != 'default-school':
        prefix = f'{school}.'
    else:
        prefix = ''

    devices_path = f'/etc/linuxmuster/sophomorix/{school}/{prefix}devices.csv'
    if not os.path.isfile(devices_path):
        return []

    with LMNFile(devices_path, 'r') as f:
        devices_data = f.read()

    ldap_data = lr.get('/devices', attributes=['cn', 'sophomorixComputerMAC', 'dn'])

    for device in devices_data:
        status = "Not registered"

        if device['room'][0] == "#":
            device['status'] = "comment"
            continue

        for ldap_device in ldap_data:
            if device['hostname'].lower() == ldap_device['cn'].lower():
                if device['mac'].lower() == ldap_device['sophomorixComputerMAC'].lower():
                    status = "Registered"
                elif "Domain Controllers" in ldap_device['dn']:
                    status = "Domain Controller"

                break

        device['status'] = status

    return devices_data

# TODO: sort inconsistency — returns a sorted list, while GET /roles/ (same kind of data:
# list of role names) returns an unsorted set().
@router.get("/roles", name="List the computer roles a device may have")
def get_computer_roles(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List the roles that are valid in the sophomorixRole column of devices.csv.

    Read from sophomorix.ini, so an installation that defines its own roles gets
    them. Unlike GET /roles, which reports the roles currently present in LDAP,
    this is the set a device may be assigned — the two differ on any server where
    a valid role is not in use yet.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Valid computer roles, sorted
    :rtype: list
    """


    try:
        return sorted(SophomorixIni().computerrole)
    except (KeyError, configparser.Error) as e:
        # ConfigParser.read() ignores a missing or unreadable file, and the
        # constructor then reads a section this endpoint never asked for, so an
        # unreadable ini surfaces as KeyError('ROLE_USER') — an error about user
        # roles from the computer roles endpoint.
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read the computer roles from the sophomorix ini: {e!r}",
        )

@router.get("/{device}", name="Get device details")
def get_device_details(device: str, credentials: bool = False, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get the details of a specific device.
    If the request is made from a global administrator, the response will contain
    all devices with the same cn accross all schools.

    Output information are e.g. cn, dn, etc...

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All devices details
    :rtype: dict
    """


    devices_data = lr.get(f'/devices/{device}', school=who.school)

    if credentials:
        device_manager = DeviceManager()
        devices_data.update(device_manager.get_credentials(device))

    if devices_data:
        return devices_data

    raise HTTPException(status_code=404, detail=f"Device {device} not found")

@router.patch("/{device}", name="Update some attributes of a specific device")
def modify_device(device: str, device_details: Device, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Update some attributes of a specific device

    *device_details* are the attributes of the device, like *unicodePwd*,

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param device: cn of the device to update
    :type device: basestring
    :param device_details: Parameter of the device, see Device attributes
    :type device_details: Device
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all devices details (dict)
    :rtype: list
    """


    # School must be given specific to avoid conflicts between clients with same
    # names upon schools. school-administrators are restricted to their own
    # school: device_details.school is only honored for global-administrators,
    # who are not scoped to a single school.
    if who.school == 'global':
        if not device_details.school:
            raise HTTPException(status_code=400, detail=f"For a request as globaladministrator, the school must be specified.")

        school = device_details.school
    else:
        school = who.school

    device_writer = LMNDevice(device, school=school)
    sam = device_writer.getattr('sAMAccountName')

    if not sam:
       raise HTTPException(status_code=404, detail=f"Device {device} not found.")

    ucPwd_hash = device_details.unicodePwd_hash
    suppCred_hash = device_details.supplementalCredentials_hash

    if ucPwd_hash or suppCred_hash:
        if not (ucPwd_hash and suppCred_hash):
            raise HTTPException(status_code=400, detail=f"Both unicodePwd_hash and supplementalCredentials_hash must be given.")

        device_manager = DeviceManager()
        device_manager.set_credentials(device, ucPwd_hash, suppCred_hash)

    elif device_details.unicodePwd:
        device_writer.setattr(data={'unicodePwd': device_details.unicodePwd})

    return device_writer.data

@router.post("/list/{school}", name="Write content of devices.csv")
@require_school
def post_management_list_content(school: str, content: MgmtList, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Write the content of devices list (file like /etc/linuxmuster/sophomorix/default-school/devices.csv).
    The school must be extra given, because it's not possible to know which school a global-administrator would like
    to request. This will overwrite the content of the CSV file, but LMNFile automatically makes a backup of the old
    CSV file.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param school: A valid school where to post the content
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param content: Content of the CSV, see MgmtList attributes
    :type content: MgmtList
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    if school != 'default-school':
        prefix = f'{school}.'
    else:
        prefix = ''

    path = f"/etc/linuxmuster/sophomorix/{school}/{prefix}devices.csv"

    # Filter status key if given
    for d in content.data:
        if 'status' in d:
            del d['status']

    try:
        with LMNFile(path, 'w') as devices_file:
            return devices_file.write(content.data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error writing {path}: {str(e)}")

@router.get("/list/{school}/import-devices", name="Run linuxmuster-import-devices")
@require_school
def do_import_devices(school: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Run linuxmuster-import-devices on the given school.
    The school must be extra given, because it's not possible to know which
    school a global-administrator would like to request.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Output of sophomorix-check
    :rtype: dict
    """


    cmd = ['linuxmuster-import-devices', '--school', school]
    results = subprocess.run(cmd, stdout=subprocess.PIPE)

    return results.stdout.decode()