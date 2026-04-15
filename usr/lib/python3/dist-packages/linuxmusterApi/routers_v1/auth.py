from fastapi import APIRouter, Depends

from security import BasicAuthChecker, AuthenticatedUser, RoleChecker, RateLimiter


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="Basic auth to get a valid JWT", dependencies=[Depends(RateLimiter(requests_limit=5, time_window=60))])
def get_json_web_token(auth: bool = Depends(BasicAuthChecker())):
    """
    ## Check user's password and respond with a valid jwt.

    ### Access
    - all users
    - rate limited to 5 requests per minute
    """

    return auth

@router.get("/whoami", name="Check authenticated user")
def get_whoami(who: AuthenticatedUser = Depends(RoleChecker("GSTsPF"))):
    """
    ## Retrieve user's jwt information.

    ### Access
    - all users
    """

    return who.model_dump()