"""
The purpose of this file is to gather all classes used as model for post data.
"""

from pydantic import BaseModel, Field, IPvAnyAddress

class UserList(BaseModel):
    """
    A list of samaccountname from users, for starting a project, add to wifi group, etc ...
    """


    users: list | None = None

class LMNShareQuota(BaseModel):
    """
    Model for quotas of shares.
    """


    comment: str | None = '---'
    quota: int
    share: str

class Group(BaseModel):
    """
    Model to create or update a sophomorix-group.
    """


    description: str | None = ''
    displayName: str | None = ''
    hide: bool = False
    join: bool = True
    mailalias: bool = False
    maillist: bool = False
    mailquota: int | None = None
    members: list = []
    proxyAddresses: list | None = []
    quota: list[LMNShareQuota] | None = []
    school: str = 'default-school'
    sophomorixCustom1: str | None = ''
    sophomorixCustom2: str | None = ''
    sophomorixCustom3: str | None = ''
    sophomorixCustom4: str | None = ''
    sophomorixCustom5: str | None = ''
    sophomorixCustomMulti1: list | None = []
    sophomorixCustomMulti2: list | None = []
    sophomorixCustomMulti3: list | None = []
    sophomorixCustomMulti4: list | None = []
    sophomorixCustomMulti5: list | None = []

class Printer(BaseModel):
    """
    Model to handle a printer group.
    """


    addmembers: list = []
    addmembergroups: list = []
    description: str | None = ''
    displayName: str | None = ''
    join: bool = True
    hide: bool = False
    removemembers: list = []
    removemembergroups: list = []
    school: str = 'default-school'

class Project(BaseModel):
    """
    Model to create a new project.
    """


    admins: list = []
    admingroups: list = []
    description: str | None = ''
    displayName: str | None = ''
    join: bool = True
    hide: bool = False
    mailalias: bool = False
    maillist: bool = False
    mailquota: int | None = None
    members: list = []
    membergroups: list = []
    proxyAddresses: list | None = []
    quota: list[LMNShareQuota] | None = []
    school: str = 'default-school'

class SchoolclassAttr(BaseModel):
    """
    Model to patch some attributes of a specific schoolclass.
    """


    description: str | None = ''
    displayName: str | None = ''
    join: bool = True
    hide: bool = False
    mailalias: bool = False
    maillist: bool = False
    mailquota: int | None = None

class User(BaseModel):
    """
    Model to patch user's data.
    """


    children: str | None = []
    givenName: str | None = ''
    displayName: str | None = ''
    mailalias: bool = False
    name: str | None = ''
    parents: list | None = []
    proxyAddresses: list | None = []
    sn: str | None = ''
    sophomorixCustom1: str | None = ''
    sophomorixCustom2: str | None = ''
    sophomorixCustom3: str | None = ''
    sophomorixCustom4: str | None = ''
    sophomorixCustom5: str | None = ''
    sophomorixCustomMulti1: list | None = []
    sophomorixCustomMulti2: list | None = []
    sophomorixCustomMulti3: list | None = []
    sophomorixCustomMulti4: list | None = []
    sophomorixCustomMulti5: list | None = []
    thumbnailPhoto: str | None = None

class SetFirstPassword(BaseModel):
    """
    Wenn setting the first password, the set_current boolean flag indicates if the current password must be overwritten
    too. If password is omitted, the current password is instead reset back to the existing first password.
    """


    password: str | None = None
    set_current: bool = Field(default= False)

class SetCurrentPassword(BaseModel):
    """
    Wenn setting the current password, the set_first boolean flag indicates if the first password must be overwritten
    too.
    """


    password: str
    set_first: bool= Field(default= False)

class StopExam(BaseModel):
    """
    users is a list of samaccountname from whom stop the exam. The attribute group_type (like "schoolclass") and
    group_name (like "8a") are used to build the path name of the directory which will contain the collected files.
    """


    users: list | None = None
    group_type: str | None = None
    group_name: str | None = None

class PrintPasswordsSchoolclassesParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """


    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = True
    school: str | None = ''
    nosplit_names: bool | None = False
    schoolclasses: list

class PrintPasswordsProjectsParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """


    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = False
    school: str | None = ''
    projects: list

class PrintPasswordsUsersParameter(BaseModel):
    """
    Parameter to fix the use of pdflatex or choose to print only one password per page.
    The parameter school could be useful for global administrators.
    format may be pdf or csv.
    """


    format: str | None = 'pdf'
    one_per_page: bool | None = False
    pdflatex: bool | None = False
    school: str | None = ''
    users: list

class MgmtList(BaseModel):
    """
    Content of a management file list like /etc/linuxmuster/sophomorix/default-school/teachers.csv
    data should be a list of dict, with one dict per line.
    """


    data: list | None = None

class Device(BaseModel):
    """
    Some attributes which can be directly modified in ldap, without breaking
    the synchronisation between ldap and devices.csv.
    """


    displayName: str | None = None
    school: str | None = None
    supplementalCredentials_hash: str | None = None
    unicodePwd: str | None = None
    unicodePwd_hash: str | None = None

class Subnet(BaseModel):
    """
    One line of /etc/linuxmuster/subnets.csv.

    All fields are optional so that comment and empty lines (whose *network*
    field then starts with '#') can be round-tripped without loss.
    """


    network: str | None = None
    routerIp: str | None = None
    beginRange: str | None = None
    endRange: str | None = None
    nameServer: str | None = None
    nextServer: str | None = None
    setupFlag: str | None = None

class SubnetList(BaseModel):
    """
    Content of /etc/linuxmuster/subnets.csv, one Subnet per line.
    """


    data: list[Subnet] | None = None

# --- LINBO Models ---

class LinboBatchMacs(BaseModel):
    """
    List of MAC addresses for LINBO host query.
    """


    macs: list[str]

class LinboHostScanBody(BaseModel):
    """
    MAC addresses to probe for online status. Empty means every client of the school.

    Kept separate from LinboBatchMacs despite the same single field: an empty list
    means "every client" here, while on /linbo/hosts/query it would reach
    Devices.filter() with no filter at all and return every device of the school.
    """


    macs: list[str] = []

class LinboWolBody(BaseModel):
    """
    MAC addresses to wake, with the magic packet parameters.

    The packet parameters are bounded here rather than in the router: an
    unbounded count is multiplied by the number of MAC addresses inside a
    blocking send loop, and an unvalidated broadcast address makes the server
    send UDP to any host it can reach.
    """


    macs: list[str]
    broadcast: IPvAnyAddress | None = None
    port: int = Field(9, ge=1, le=65535)
    count: int = Field(3, ge=1, le=10)

class StartConfRawBody(BaseModel):
    """
    Raw start.conf content, keeps comments, but will not be parsed.
    """

    content: str

class LinboImageNameBody(BaseModel):
    """
    Target name for a rename or duplicate, validated as a linbo image name by
    the endpoint before it reaches LinboImageManager.
    """


    new_name: str

class LinboImageExtrasBody(BaseModel):
    """
    Content of an image's sidecar files, as LinboImage.save_extras expects it.

    A field left out or set to null deletes that sidecar — that is
    save_extras' own semantics, not something the endpoint adds. desc is the
    exception: an empty string writes an empty file.

    info is required for exactly that reason. LinboImage.load_info parses it
    for every image that is not a backup and raises IncompleteImageInfoError
    without it, so letting a request omit it would leave the image unreadable
    for the manifest, for LINBO and for any later call to this endpoint.
    """


    info: str
    desc: str | None = None
    vdi: str | None = None
    reg: str | None = None
    postsync: str | None = None
    prestart: str | None = None

class LinboRemoteRunBody(BaseModel):
    """
    Parameters to build and run a linbo-remote command via LinboRemote.

    Exactly one of group, room or clients must be given — LinboRemote itself
    validates that (and everything else: unknown commands, nr out of range
    for the target's start.conf, etc.), surfaced as a 400 if it rejects them.
    """


    cmd: str
    group: str | None = None
    room: str | None = None
    clients: list[str] = []
    wait: int = 0
    wol: int = 0
    disable_gui: bool = False
    broadcast: bool = False
    bypass: bool = False
    onboot: bool = False

class LinboDriverProfileCreate(BaseModel):
    """
    Data required to create a hardware-matched driver profile.
    """


    name: str
    vendor: str
    product: str

class LinboDriverMatchUpdate(BaseModel):
    """
    Hardware matching values for an existing driver profile.
    """


    vendor: str
    product: str

class LinboDriverImageAssignment(BaseModel):
    """
    LINBO image assigned to a driver profile.
    """


    image: str

# --- Password constraints models ---

class PasswordRuleEntry(BaseModel):
    """
    One password rule, see linuxmusterTools.passwords.PasswordRules.build for
    the supported "type" values ("min_length", "require_classes") and which
    of the fields below each of them uses.
    """


    type: str
    value: int | None = None
    classes: list[str] | None = None
    count: int | None = None

class PasswordConstraintsConfig(BaseModel):
    """
    Full content of /etc/linuxmuster/tools/password_constraints.yml.

    "default" holds the per-role rules applied to every school unless
    overridden; "schools" holds per-school, per-role overrides. Writing this
    is restricted for school-administrators to their own school's entry in
    "schools", see the passwordconstraints router.
    """


    default: dict[str, list[PasswordRuleEntry]] | None = None
    schools: dict[str, dict[str, list[PasswordRuleEntry]]] | None = None

class DomainPasswordPolicy(BaseModel):
    """
    Samba AD domain-wide password policy, see
    linuxmusterTools.samba_util.DomainPasswordSettingsManager.set(). All
    fields are optional: only the given ones are changed, the rest of the
    domain policy (history length, lockout settings, PSOs) is left as-is.
    """


    min_pwd_length: int | None = None
    min_pwd_age: int | None = None
    max_pwd_age: int | None = None
    complexity: bool | None = None
