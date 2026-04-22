# VDI API Documentation

REST endpoints for managing VDI (Virtual Desktop Infrastructure) desktops under `/v1/vdi/`.

These endpoints are provided by the optional [edulution-linbo-vdi](https://github.com/edulution-io/edulution-linbo-vdi) package. If the package is not installed, all endpoints return `501 Not Implemented`.

## Authentication

All endpoints require the standard `X-API-Key` header with a valid JWT (obtained via `POST /v1/auth/`). Host-key auth (`X-HOST-Key`) is also supported.

```
X-API-Key: <jwt-token>
```

## Base URL

```
https://<server>/v1/vdi
```

---

## Endpoints overview

| Method | Path | Access | Description |
|---|---|---|---|
| GET | `/groups` | all users | List available VDI groups (images) |
| GET | `/clones` | all users | Clone status for all groups |
| GET | `/clones/{group}` | all users | Clone status for a specific group |
| GET | `/masters` | admins only | Master status for all groups |
| POST | `/connection` | all users | Request a SPICE connection |

---

## GET `/v1/vdi/groups`

List all available VDI groups (images) with their configuration.

**Access:** all authenticated users

### Request

```http
GET /v1/vdi/groups HTTP/1.1
X-API-Key: <jwt>
```

### Response `200 OK`

```json
[
    {
        "name": "debian-vdi",
        "activated": true,
        "ostype": "l26",
        "cores": 4,
        "memory": 4096,
        "minimum_vms": 3,
        "maximum_vms": 10,
        "prestarted_vms": 1
    },
    {
        "name": "win10-vdi",
        "activated": false,
        "ostype": "win10",
        "cores": 4,
        "memory": 8192,
        "minimum_vms": 5,
        "maximum_vms": 20,
        "prestarted_vms": 2
    }
]
```

### Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Group name (matches `start.conf.<name>`) |
| `activated` | boolean | Whether the group is active |
| `ostype` | string | Proxmox ostype (`win10`, `win11`, `l26`, ...) |
| `cores` | integer | CPU cores per VM |
| `memory` | integer | RAM per VM in MB |
| `minimum_vms` | integer | Minimum clones kept running |
| `maximum_vms` | integer | Maximum clones the pool may scale to |
| `prestarted_vms` | integer | Clones kept pre-started for fast assignment |

---

## GET `/v1/vdi/clones`

Get the clone status for all VDI groups.

**Access:** all authenticated users

### Request

```http
GET /v1/vdi/clones HTTP/1.1
X-API-Key: <jwt>
```

### Response `200 OK`

```json
{
    "debian-vdi": {
        "summary": {
            "allocated_vms": 2,
            "available_vms": 3,
            "existing_vms": 5,
            "registered_vms": 10,
            "building_vms": 0,
            "failed_vms": 0
        },
        "clone_vms": {
            "61801": {
                "vmid": "61801",
                "name": "debian-vdi-clone-61801",
                "status": "running",
                "uptime": 12450,
                "buildstate": "finished",
                "dateOfCreation": "20260415172030",
                "image": "debian13.qcow2",
                "master": "61701",
                "group": "debian-vdi",
                "imagesize": "9702146048",
                "room": "vdi",
                "hostname": "vdi-client01",
                "ip": "10.0.0.201",
                "mac": "aa:ee:4e:b5:5c:01",
                "user": "teacher01",
                "lastConnectionRequestUser": "teacher01",
                "lastConnectionRequestTime": "20260415205512"
            },
            "61802": {
                "vmid": "61802",
                "name": "debian-vdi-clone-61802",
                "status": "running",
                "uptime": 8120,
                "buildstate": "finished",
                "dateOfCreation": "20260415172145",
                "image": "debian13.qcow2",
                "master": "61701",
                "group": "debian-vdi",
                "room": "vdi",
                "hostname": "vdi-client02",
                "ip": "10.0.0.202",
                "mac": "aa:ee:4e:b5:5c:02",
                "user": "",
                "lastConnectionRequestUser": "",
                "lastConnectionRequestTime": ""
            }
        }
    }
}
```

### Summary fields

| Field | Description |
|---|---|
| `allocated_vms` | Clones currently assigned to a user |
| `available_vms` | Finished clones ready for assignment |
| `existing_vms` | Clones that exist in Proxmox |
| `registered_vms` | Clones registered in `devices.csv` |
| `building_vms` | Clones currently being provisioned |
| `failed_vms` | Clones that failed to build |

### Clone VM fields

| Field | Type | Description |
|---|---|---|
| `vmid` | string | Proxmox VM ID |
| `name` | string | VM name in Proxmox |
| `status` | string | `running`, `stopped`, `paused`, ... |
| `uptime` | integer | Seconds since start |
| `buildstate` | string | `building`, `finished`, `failed` |
| `dateOfCreation` | string | `YYYYMMDDHHmmss` creation timestamp |
| `image` | string | Base image file used |
| `master` | string | Source master VMID |
| `user` | string | Currently logged-in user (empty if none) |
| `lastConnectionRequestUser` | string | Last user who requested this VM |
| `lastConnectionRequestTime` | string | `YYYYMMDDHHmmss` timestamp of last request |
| `hostname` | string | Hostname from `devices.csv` |
| `ip` | string | IP address |
| `mac` | string | MAC address |

---

## GET `/v1/vdi/clones/{group}`

Get the clone status for a specific VDI group.

**Access:** all authenticated users

### Request

```http
GET /v1/vdi/clones/debian-vdi HTTP/1.1
X-API-Key: <jwt>
```

### Response `200 OK`

Same structure as the group value in `/clones`, e.g.:

```json
{
    "summary": {
        "allocated_vms": 1,
        "available_vms": 2,
        "existing_vms": 3,
        "registered_vms": 10,
        "building_vms": 0,
        "failed_vms": 0
    },
    "61801": {
        "vmid": "61801",
        "name": "debian-vdi-clone-61801",
        "status": "running",
        "buildstate": "finished",
        "ip": "10.0.0.201",
        "mac": "aa:ee:4e:b5:5c:01",
        "user": "teacher01",
        "lastConnectionRequestUser": "teacher01",
        "lastConnectionRequestTime": "20260415205512"
    }
}
```

### Error responses

| Status | Condition |
|---|---|
| `404` | VDI group does not exist |

```json
{ "detail": "VDI group 'foobar' not found" }
```

---

## GET `/v1/vdi/masters`

Get the master VM status for all groups.

**Access:** global-administrators, school-administrators

### Request

```http
GET /v1/vdi/masters HTTP/1.1
X-API-Key: <jwt>
```

### Response `200 OK`

```json
{
    "debian-vdi": {
        "summary": {
            "existing_master": 1,
            "registered": 1,
            "building_master": 0,
            "failed_master": 0,
            "finished": 1
        },
        "current_master": {
            "vmid": "61701",
            "timestamp": 20260415164820.0,
            "hostname": "vdi-master",
            "actual_imagesize": "9702146048",
            "ip": "10.0.0.50",
            "mac": "aa:ee:4e:b5:5c:00"
        },
        "master_vms": {
            "61701": {
                "vmid": "61701",
                "name": "debian-vdi-master",
                "status": "stopped",
                "uptime": 0,
                "buildstate": "finished",
                "timestamp": "20260415164820",
                "imagesize": "9702146048",
                "dateOfCreation": "20260415163516",
                "group": "debian-vdi"
            }
        }
    }
}
```

### Summary fields

| Field | Description |
|---|---|
| `existing_master` | Master VMs that exist in Proxmox |
| `registered` | VMIDs reserved for masters in `vmids` config |
| `building_master` | Masters currently being provisioned |
| `finished` | Masters successfully built (templates) |
| `failed_master` | Masters that failed to build |

---

## POST `/v1/vdi/connection`

Request a SPICE connection to a VDI desktop. Assigns an available clone to the user and returns VM details plus the SPICE connection configuration.

**Access:** all authenticated users

The broker selects a clone in this priority order:

1. A clone the user was recently assigned to (within `timeoutConnectionRequest`)
2. An unused clone (never assigned)
3. A clone whose previous assignment has timed out

### Request

```http
POST /v1/vdi/connection HTTP/1.1
X-API-Key: <jwt>
Content-Type: application/json

{
    "group": "debian-vdi",
    "user": "teacher01"
}
```

### Request body

| Field | Type | Description |
|---|---|---|
| `group` | string | Name of the VDI group |
| `user` | string | Username (sAMAccountName) to assign the desktop to |

### Response `200 OK`

```json
{
    "vm": {
        "vmid": "61801",
        "name": "debian-vdi-clone-61801",
        "ip": "10.0.0.201",
        "status": "running",
        "group": "debian-vdi"
    },
    "spice": {
        "configFile": "/tmp/vdi/start-vdi-20260415210934-XK29AB.vv"
    }
}
```

### Fields

| Field | Description |
|---|---|
| `vm.vmid` | Proxmox VM ID of the assigned clone |
| `vm.name` | VM name in Proxmox |
| `vm.ip` | IP address of the VM |
| `vm.status` | VM power status (`running`, ...) |
| `vm.group` | VDI group name |
| `spice.configFile` | Path to the generated SPICE `.vv` connection file |

The `configFile` contains a standard `virt-viewer` configuration block and can be opened directly with `remote-viewer`, `virt-viewer`, or a SPICE-compatible browser plugin. The file is automatically cleaned up after ~1 minute.

### Example SPICE config file content

```ini
[virt-viewer]
type=spice
host-subject=...
delete-this-file=1
secure-attention=ctrl+alt+ins
toggle-fullscreen=shift+f11
title=debian-vdi-clone-61801
tls-port=61000
proxy=http://server.demo.multi.schule:3128
password=xxxxxxxx
release-cursor=shift+f12
host=10.0.0.10
ca=-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----
```

### Error responses

| Status | Condition | Detail |
|---|---|---|
| `404` | VDI group not found | `VDI group 'foo' not found` |
| `503` | No desktop available | `No desktop available for user 'teacher01' in group 'debian-vdi'` |
| `500` | Internal error | Error details |

```json
{ "detail": "No desktop available for user 'teacher01' in group 'debian-vdi'" }
```

---

## Common error responses

### `401 Unauthorized`

Missing or invalid `X-API-Key`.

```json
{ "detail": "Invalid token." }
```

### `403 Forbidden`

User role does not have access to the endpoint (e.g. student trying to access `/masters`).

```json
{ "detail": "Permission denied." }
```

### `501 Not Implemented`

The `edulution-linbo-vdi` package is not installed on the API server.

```json
{ "detail": "edulution-linbo-vdi is not installed on this server." }
```

### `500 Internal Server Error`

Unexpected error (Proxmox connection failure, config error, ...).

```json
{ "detail": "Failed to initialize VDI context: <error>" }
```

---

## Example workflow

1. **Authenticate** and get a JWT:

   ```bash
   curl -u user:password https://server/v1/auth/
   # → {"access_token": "eyJ...", "token_type": "bearer"}
   ```

2. **Discover available VDI groups:**

   ```bash
   curl -H "X-API-Key: eyJ..." https://server/v1/vdi/groups
   ```

3. **Request a desktop for the logged-in user:**

   ```bash
   curl -X POST \
     -H "X-API-Key: eyJ..." \
     -H "Content-Type: application/json" \
     -d '{"group":"debian-vdi","user":"teacher01"}' \
     https://server/v1/vdi/connection
   ```

4. **Connect to the returned `configFile`** with `remote-viewer`:

   ```bash
   remote-viewer /tmp/vdi/start-vdi-20260415210934-XK29AB.vv
   ```
