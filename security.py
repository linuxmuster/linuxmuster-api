from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from starlette import status


X_API_KEY = APIKeyHeader(name='X-API-Key')

async def check_authentication_header(x_api_key: str = Depends(X_API_KEY)):
    """ takes the X-API-Key header and converts it into the matching user object from the database """

    # incredible strong password for test purpose
    if x_api_key == "123":
        return {
            "id": 123,
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key",
    )
