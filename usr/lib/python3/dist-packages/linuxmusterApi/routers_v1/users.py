from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, UserChecker, AuthenticatedUser, UserListChecker
from .body_schemas import SetFirstPassword, SetCurrentPassword, UserList, User
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector import LMNLdapWriter as lw
from linuxmusterTools.samba_util import UserManager
import linuxmusterTools.quotas


user_manager = UserManager()

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all users")
def get_all_users(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get basic informations from all users.

    Output informations are sn, givenName, sophomorixRole, sophomorixAdminClass.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    return lr.get('/users', attributes=['sn', 'givenName', 'sophomorixRole', 'sophomorixAdminClass'])

@router.get("/{user}", name="User details")
def get_user(user: str, check_first_pw: bool = False, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get all informations of a specific user.
    The optional query parameter `check_first_pw` is a boolean. If set to true, the endpoint will check if the first
    password is still set, in a key `FirstPasswordSet`. If the permissions are not sufficient, the key
    `FirstPasswordSet` will contain an error message.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    if check_first_pw:
        user_details = lr.get(f'/users/{user}', dict=False)
        first_pw_set = user_details.test_first_password()
        user_dict = user_details.asdict()
        user_dict['FirstPasswordSet'] = first_pw_set
        return user_dict
    else:
        return lr.get(f'/users/{user}')

@router.post("/{user}", name="Update user's data")
def post_user_data(user: str, user_details: User, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Update the data of a specific user

    *user_details* are the attributes of the user, like *displayName*,
    *proxyAddresses*, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers
    - students

    \f
    :param user: cn of the user to update
    :type user: basestring
    :param user_details: Parameter of the user, see User attributes
    :type user_details: User
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """

    if user_details.proxyAddresses:
        lw.setattr_user(f"{user.lower()}", data={'proxyAddresses': user_details.proxyAddresses})

    if user_details.displayName:
        lw.setattr_user(f"{user.lower()}", data={'displayName': user_details.displayName})

@router.post("/get_users_from_cn", name="User details")
def get_users_from_cn(userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Get all informations of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """

    response = {}
    for user in userlist.users:
        if user not in response:
            response[user] = lr.get(f'/users/{user}')

    return response

@router.post("/{user}/set-first-password", name="Set user's first password")
def set_first_user_password(user: str, password: SetFirstPassword, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Set the first password of the user.

    The **first password**, also known as default password, is the readable password
    in the LDAP account, and the one to which it's possible to retrograde if the
    user looses its **current password**.
    If the flag *set_current* is set to true, the current password will be updated
    too.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param password: The password o set
    :type password: SetFirstPassword
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    # TODO : paswword constraints ?
    lw.setattr_user(user, data={'sophomorixFirstPassword': password.password})
    if password.set_current:
        try:
            user_manager.set_password(user, password.password)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Cannot set current password: {str(e)}")

@router.post("/{user}/set-current-password", name="Set user's current password")
def set_current_user_password(user: str, password: SetCurrentPassword, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Set the current password of the user.

    The **current password** is the password actually used by the user, not
    readable in the LDAP tree.

    The **first password**, also known as default password, is the readable password
    in the LDAP account, and the one to which it's possible to retrograde if the
    user looses its **current password**.
    If the flag *set_first* is set to true, the first password will be updated
    too.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    ### TODO
    - Password constraints ?

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param password: The password o set
    :type password: SetCurrentPassword
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    try:
        user_manager.set_password(user, password.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if password.set_first:
        lw.setattr_user(user, data={'sophomorixFirstPassword': password.password})


@router.get("/{user}/quotas", name='Get the quotas of a specific user')
def get_user_quotas(user: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get the actual quotas of a specific user.

    Given informations per share are: used quota, soft limit and hard limit.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All available per share quota informations
    :rtype: dict
    """


    try:
       return linuxmusterTools.quotas.get_user_quotas(user)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))