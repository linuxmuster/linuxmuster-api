from .models import LMNTestUser


# Path to local linuxmuster api main module,
# like /home/dev/api/usr/lib/python3/dist-packages/linuxmusterApi/
LOCAL_API_PATH = '/APIPATH/usr/lib/python3/dist-packages/linuxmusterApi/'

# Base url to test
BASE_URL = "https://127.0.0.1:8001/v1"

# List of users to test
GLOBALADMIN = LMNTestUser(cn="global-admin", password="PASSWORD", role="globaladministrator", school="global")
SCHOOLADMIN = LMNTestUser(cn="school-admin", password="PASSWORD", role="schooladministrator", school="default-school")
TEACHER = LMNTestUser(cn="teacher01", password="PASSWORD", role="teacher", school="default-school")
STUDENT = LMNTestUser(cn="student01", password="PASSWORD", role="student", school="default-school")
STAFF = LMNTestUser(cn="staff01", password="PASSWORD", role="staff", school="default-school")
PARENT = LMNTestUser(cn="parent01", password="PASSWORD", role="parent", school="default-school")