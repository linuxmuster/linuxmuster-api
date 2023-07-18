from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from starlette import status


X_API_KEY = APIKeyHeader(name='X-API-Key')

async def check_authentication_header(x_api_key: str = Depends(X_API_KEY)):
    """
    Return role associated with the api key.
    """

    # Must read from config file
    api_keys = {
        "1": "globaladministrator",
        "2": "schooladministrator",
        "3": "teacher",
        "4": "student"
    }

    # incredible strong password for test purpose
    if x_api_key in api_keys:
        return api_keys[x_api_key]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key",
    )

class PermissionChecker:
    """
    Check role for permission access. Missing the possibility to check the user:
    globaladmin can access all user informations, but an user should be able to
    access its own informations.
    """

    def __init__(self, roles) -> None:
        if isinstance(roles, list):
            self.roles = roles
        elif isinstance(roles, str):
            self.roles = [roles]

    def __call__(self, group: str = Depends(check_authentication_header)) -> bool:
        if group in self.roles:
            return True

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied'
        )

