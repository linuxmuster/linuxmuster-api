from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserChecker, AuthenticatedUser, UserListChecker
from .body_schemas import SetFirstPassword, SetCurrentPassword, UserList, User
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector import LMNUser, LMNStudent
from linuxmusterTools.passwords import PasswordPolicyProvider
import linuxmusterTools.quotas
from utils.checks import get_user_or_404


password_policy_provider = PasswordPolicyProvider()

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


    user_details = get_user_or_404(user, who.school)

    if check_first_pw:
        user_details = lr.get(f'/users/{user}', as_dict=False, school=who.school)
        first_pw_set = user_details.test_first_password()
        user_dict = user_details.as_dict()
        user_dict['FirstPasswordSet'] = first_pw_set
        return user_dict
    else:
        return user_details

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


    get_user_or_404(user, who.school)

    data = {}
    for key, value in user_details.__dict__.items():
        if (key == "thumbnailPhoto" and value is not None) or value:
            data[key] = value

    UserWriter = LMNUser(user.lower(), who.school)
    UserWriter.setattr(data=data)


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
            # Since the cn is given and uniq across schools, no need to specify the school
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


    user_details = get_user_or_404(user, who.school)

    result = password_policy_provider.validate(
        password.password, role=user_details.sophomorixRole, school=who.school, username=user
    )
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(result.violations)}",
        )

    UserWriter = LMNUser(user, who.school)
    UserWriter.setattr(data={'sophomorixFirstPassword': password.password})
    if password.set_current:
        try:
            UserWriter.set_actual_password(password.password)
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

    \f
    :param user: The user to get the details from (samaccountname)
    :type user: basestring
    :param password: The password o set
    :type password: SetCurrentPassword
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    user_details = get_user_or_404(user, who.school)

    result = password_policy_provider.validate(
        password.password, role=user_details.sophomorixRole, school=who.school, username=user
    )
    if not result.ok:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(result.violations)}",
        )

    UserWriter = LMNUser(user.lower(), school=who.school)
    try:
        UserWriter.set_actual_password(password.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if password.set_first:
        UserWriter.setattr(data={'sophomorixFirstPassword': password.password})


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


    get_user_or_404(user, who.school)

    try:
       return linuxmusterTools.quotas.get_user_quotas(user)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{user}/parents", name='Add parents to a specific user')
def add_user_parent(user: str, parents: UserList, who: AuthenticatedUser = Depends(UserChecker("GS"))):
    """
    ## Add parents to a specific user.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param parents: samaccountname of the parents to add
    :type parents: list
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not parents:
        raise HTTPException(status_code=400, detail=f"You need to specify at least one parent cn.")

    get_user_or_404(user, who.school)

    UserWriter = LMNStudent(user.lower(), school=who.school)
    UserWriter.add_parents(parents.users)

@router.delete("/{user}/parents", name='Delete parents from a specific user')
def delete_user_parents(user: str, parents: UserList, who: AuthenticatedUser = Depends(UserChecker("GS"))):
    """
    ## Delete parents from a specific user.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param user: samaccountname of the user to check
    :type user: basestring
    :param parents: samaccountname of the parents to delete
    :type parents: list
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not parents:
        raise HTTPException(status_code=400, detail=f"You need to specify at least one parent cn.")

    get_user_or_404(user, who.school)

    UserWriter = LMNStudent(user.lower(), school=who.school)
    UserWriter.remove_parents(parents.users)
