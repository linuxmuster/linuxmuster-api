from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.lmnfile import LMNFile
from utils.checks import get_printer_or_404
from utils.sophomorix import lmn_getSophomorixValue
from .body_schemas import Printer


router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}", name="List all devices")
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

    with LMNFile(f'/etc/linuxmuster/sophomorix/{school}/{prefix}devices.csv', 'r') as f:
        devices_data = list(filter(lambda d:d['room'][0] != "#", f.read()))
        devices_data = sorted(devices_data, key=lambda d: (d['room'], d['hostname']))

    ldap_data = lr.get('/devices', attributes=['cn', 'sophomorixComputerMAC', 'dn'])

    for device in devices_data:
        for ldap_device in ldap_data:
            if device['hostname'].lower() == ldap_device['cn'].lower():
                if device['mac'].lower() == ldap_device['sophomorixComputerMAC'].lower():
                    status = "Registered"
                elif "Domain Controllers" in ldap_device['dn']:
                    status = "Domain Controller"

                break
        else:
            status = "Not registered"

        device['status'] = status

    return devices_data