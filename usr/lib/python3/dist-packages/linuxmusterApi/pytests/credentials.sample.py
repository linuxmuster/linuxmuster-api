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

# Test data — fill with actual values from your LDAP
SCHOOL = 'default-school'
SCHOOLCLASS = 'SCHOOLCLASSNAME'  # CN of an existing schoolclass
EXTRACLASS = 'EXTRACLASSNAME'    # CN of an existing extraclass
PROJECT = 'p_PROJECTNAME'        # CN of an existing project (with prefix)
PRINTER = 'PRINTERNAME'          # CN of an existing printer
MGMT_GROUP = 'MGMTGROUPNAME'     # CN of an existing management group
GROUP = 'GROUPNAME'              # CN of an existing group