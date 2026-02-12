from pydantic import BaseModel


# Path to local linuxmuster api main module,
# like /home/dev/api/usr/lib/python3/dist-packages/linuxmusterApi/
LOCAL_API_PATH = '/APIPATH/usr/lib/python3/dist-packages/linuxmusterApi/'

# Base url to test
BASE_URL = "https://127.0.0.1:8001/v1"

# Basic test user class with pydantic
class LMNTestUser(BaseModel):
    cn: str
    password: str
    role: str
    school: str

# List of users to test
USERS = [
    LMNTestUser(cn="global-admin", password="PASSWORD", role="globaladministrator", school="global"),
    LMNTestUser(cn="school-admin", password="PASSWORD", role="schooladministrator", school="default-school"),
    LMNTestUser(cn="teacher01", password="PASSWORD", role="teacher", school="default-school"),
    LMNTestUser(cn="student01", password="PASSWORD", role="student", school="default-school"),
]