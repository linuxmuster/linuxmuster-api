import os
import subprocess
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNDevice
from linuxmusterTools.lmnfile import LMNFile
from utils.checks import get_printer_or_404
from utils.sophomorix import lmn_getSophomorixValue
from .body_schemas import MgmtList, Device
from utils.checks import check_valid_school_or_404

router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
    responses={404: {"description": "Not found"}},
)

@router.get("/list/{school}", name="List all devices")
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


    check_valid_school_or_404(school)

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

@router.get("/{device}", name="Get device details")
def get_device_details(device: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get the details of a specific device.

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


    # School specific request. For global-admins, it will search in all devices from all schools
    device_writer = LMNDevice(device, school=who.school)

    if not device_writer.getattr('sAMAccountName'):
       raise HTTPException(status_code=404, detail=f"Device {device} not found.")

    device_writer.setattr(data=device_details.model_dump())

    return device_writer.data

@router.post("/list/{school}", name="Write content of devices.csv")
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


    check_valid_school_or_404(school)

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


    check_valid_school_or_404(school)

    cmd = ['linuxmuster-import-devices', '--school', school]
    results = subprocess.run(cmd, stdout=subprocess.PIPE)

    return results.stdout.decode()