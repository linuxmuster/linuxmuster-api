from fastapi import APIRouter, Depends, HTTPException, Request

from security import BasicAuthChecker


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_json_web_token(auth: bool = Depends(BasicAuthChecker())):
    """
    Check user's password and send a valid jwt.
    """

    return auth