from fastapi import APIRouter, Depends, HTTPException, Request

from security import BasicAuthChecker


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="Basic auth to get a valid JWT")
def get_json_web_token(auth: bool = Depends(BasicAuthChecker())):
    """
    ## Check user's password and respond with a valid jwt.

    ### Access
    - all users
    """

    return auth