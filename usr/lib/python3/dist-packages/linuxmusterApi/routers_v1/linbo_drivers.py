"""REST endpoints for LINBO Windows driver profiles.

The router only translates HTTP requests and errors. Hardware inventory,
profile metadata, image assignments and driverpostsync publication remain in
the corresponding ``linuxmusterTools.linbo`` managers.
"""

from fastapi import APIRouter, Depends, HTTPException

from linuxmusterTools.linbo import (
    DriverProfileExistsError,
    LinboDriverManager,
    LinboHardwareInventoryManager,
    LinboImageManager,
)
from security import AuthenticatedUser, RoleChecker
from utils.checks import check_valid_school_or_404, require_school
from .body_schemas import (
    LinboDriverImageAssignment,
    LinboDriverMatchUpdate,
    LinboDriverProfileCreate,
)


router = APIRouter(
    prefix="/linbo/drivers",
    tags=["LINBO Drivers"],
    responses={404: {"description": "Not found"}},
)


def _raise_driver_http_error(error):
    """Translate expected linuxmuster-tools errors without changing them."""

    if isinstance(error, (DriverProfileExistsError, PermissionError)):
        status_code = 409
    elif isinstance(error, FileNotFoundError):
        status_code = 404
    else:
        status_code = 400
    raise HTTPException(status_code=status_code, detail=str(error)) from error


def _profile_response(profile):
    """Remove the internal server path from a driver profile response."""

    return {
        "name": profile["name"],
        "matchConf": profile["matchConf"],
    }


@router.get("/inventory", name="List LINBO hardware inventories")
@require_school
def list_driver_inventory(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """List client hardware inventories.

    A school-administrator sees the machines of their own school only.
    """

    check_valid_school_or_404(school)
    try:
        return LinboHardwareInventoryManager(school=school).list()
    except ValueError as error:
        _raise_driver_http_error(error)


@router.get(
    "/inventory/{hostname}",
    name="Get a LINBO hardware inventory",
)
@require_school
def get_driver_inventory(
    hostname: str,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Get one client hardware inventory.

    A school-administrator can only read a machine of their own school.
    """

    check_valid_school_or_404(school)
    try:
        inventory = LinboHardwareInventoryManager(school=school).get(hostname)
    except ValueError as error:
        _raise_driver_http_error(error)

    if inventory is None:
        raise HTTPException(
            status_code=404,
            detail=f"LINBO hardware inventory '{hostname}' not found",
        )
    return inventory


@router.get("/profiles", name="List LINBO driver profiles")
def list_driver_profiles(
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """List all valid Windows driver profiles, server-wide."""

    return [
        _profile_response(profile) for profile in LinboDriverManager().list_profiles()
    ]


@router.post(
    "/profiles",
    name="Create a LINBO driver profile",
    status_code=201,
)
def create_driver_profile(
    body: LinboDriverProfileCreate,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Create a profile with one DMI match.

    **Not school-scoped.** `/srv/linbo/drivers` holds one set of profiles for
    the whole server, so a school-administrator changes here what every
    school deploys. A wrong DMI match sends drivers to hardware that is not
    theirs, and it only shows at a client's next sync.
    """

    try:
        profile = LinboDriverManager().create_profile(
            body.name,
            body.vendor,
            body.product,
        )
    except (DriverProfileExistsError, ValueError) as error:
        _raise_driver_http_error(error)
    return _profile_response(profile)


@router.get(
    "/profiles/{profile_name}",
    name="Get a LINBO driver profile",
)
def get_driver_profile(
    profile_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Get one driver profile and its DMI match, server-wide."""

    try:
        profile = LinboDriverManager().get_profile(profile_name)
    except ValueError as error:
        _raise_driver_http_error(error)

    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=f"Driver profile '{profile_name}' not found",
        )
    return _profile_response(profile)


@router.put(
    "/profiles/{profile_name}/match",
    name="Update LINBO driver profile matching",
)
def update_driver_profile_match(
    profile_name: str,
    body: LinboDriverMatchUpdate,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Replace a profile's DMI match.

    **Not school-scoped.** `/srv/linbo/drivers` holds one set of profiles for
    the whole server, so a school-administrator changes here what every
    school deploys. A wrong DMI match sends drivers to hardware that is not
    theirs, and it only shows at a client's next sync.
    """

    try:
        profile = LinboDriverManager().update_match(
            profile_name,
            body.vendor,
            body.product,
        )
    except (FileNotFoundError, ValueError) as error:
        _raise_driver_http_error(error)
    return _profile_response(profile)


@router.get(
    "/profiles/{profile_name}/image",
    name="Get a LINBO driver profile image assignment",
)
def get_driver_profile_image(
    profile_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Get a profile's optional image assignment, server-wide."""

    try:
        image = LinboImageManager().get_driver_profile_image(profile_name)
    except (FileNotFoundError, ValueError) as error:
        _raise_driver_http_error(error)
    return {"profile": profile_name, "image": image}


@router.put(
    "/profiles/{profile_name}/image",
    name="Assign an image to a LINBO driver profile",
)
def assign_driver_profile_image(
    profile_name: str,
    body: LinboDriverImageAssignment,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Assign an image and publish its hooks.

    **Not school-scoped.** `/srv/linbo/drivers` holds one set of profiles for
    the whole server, so a school-administrator changes here what every
    school deploys. A wrong DMI match sends drivers to hardware that is not
    theirs, and it only shows at a client's next sync.
    """

    try:
        return LinboImageManager().assign_driver_profile(
            profile_name,
            body.image,
        )
    except (FileNotFoundError, PermissionError, ValueError) as error:
        _raise_driver_http_error(error)


@router.delete(
    "/profiles/{profile_name}/image",
    name="Remove a LINBO driver profile image assignment",
)
def unassign_driver_profile_image(
    profile_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Unassign an image and republish its hook.

    **Not school-scoped.** `/srv/linbo/drivers` holds one set of profiles for
    the whole server, so a school-administrator changes here what every
    school deploys. A wrong DMI match sends drivers to hardware that is not
    theirs, and it only shows at a client's next sync.
    """

    try:
        return LinboImageManager().unassign_driver_profile(profile_name)
    except (FileNotFoundError, PermissionError, ValueError) as error:
        _raise_driver_http_error(error)


@router.delete(
    "/profiles/{profile_name}",
    name="Delete a LINBO driver profile",
)
def delete_driver_profile(
    profile_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """Delete an unassigned driver profile.

    **Not school-scoped.** `/srv/linbo/drivers` holds one set of profiles for
    the whole server, so a school-administrator changes here what every
    school deploys. A wrong DMI match sends drivers to hardware that is not
    theirs, and it only shows at a client's next sync.

    **No undo here.** This removes the profile directory as a whole, the INF
    payload an administrator put there included. `match.conf` and `image.conf`
    are versioned on every edit, a deletion is not: getting the payload back
    means restoring it from the server's own backups.
    """

    try:
        deleted = LinboDriverManager().delete_profile(profile_name)
    except (FileNotFoundError, ValueError) as error:
        _raise_driver_http_error(error)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Driver profile '{profile_name}' not found",
        )
    return {"deleted": True, "name": profile_name}
