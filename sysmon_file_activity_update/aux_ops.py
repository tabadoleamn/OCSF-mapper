"""
Auxiliary/custom transformations for Sysmon -> OCSF conversion.

These operations intentionally live outside ocsf_mapper.ops because they
perform source-specific transformations that the standard ocsf-mapper DSL
does not currently provide.

Supported transformations:

    windows_basename
    windows_dirname
    windows_domain_user
    sysmon_hashes_to_ocsf_fingerprints
"""

from __future__ import annotations

import ntpath
from typing import Any
from datetime import datetime, timezone, timedelta
import re
import ipaddress



_PROTOCOL_NUMBERS = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "ipv6-icmp": 58,
    "icmpv6": 58,
}


# *********************************************************
def _clean_string(value: Any) -> str | None:
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.lower() in {
        "null",
        "none",
        "nil",
        "-"
    }:
        return None

    return value


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_sysmon_bool(value: Any) -> bool | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    value = str(value).strip().lower()

    if value in {
        "true",
        "1",
        "yes",
        "y"
    }:
        return True

    if value in {
        "false",
        "0",
        "no",
        "n"
    }:
        return False

    return None


def _sysmon_event_id(
    record: dict[str, Any],
) -> int | None:
    try:
        return int(record.get("EventID"))
    except (TypeError, ValueError):
        return None


# ********************************************************

def sysmon_network_activity_name(
    record: dict[str, Any],
) -> str:

    event_id = _sysmon_event_id(record)

    if event_id is None:
        return "Unknown"

    if event_id == 3:
        return "Open"

    category = _clean_string(
        record.get("Category")
    )

    if category:
        return category

    return f"Sysmon Event {event_id}"

# *****************************************************

def sysmon_network_type_name(
    record: dict[str, Any],
) -> str:

    activity_name = (
        sysmon_network_activity_name(record)
    )

    return (
        f"Network Activity: {activity_name}"
    )

# *********************************************************

def _sysmon_network_raw_severity(
    record: dict[str, Any],
) -> Any:

    for field in (
        "Severity",
        "EventType",
        "Level",
    ):
        value = record.get(field)

        if value is not None:
            if isinstance(value, str):
                if value.strip():
                    return value
            else:
                return value

    return None

# *******************************************************

def sysmon_network_severity_id(
    record: dict[str, Any],
) -> int:

    value = _sysmon_network_raw_severity(
        record
    )

    # Native Sysmon Event ID 3 is Informational.
    if value is None:
        if _sysmon_event_id(record) == 3:
            return 1

        return 0

    # Windows Event Level numeric values.
    if isinstance(value, int):
        windows_level_map = {
            1: 5,  # Critical
            2: 4,  # Error -> High
            3: 3,  # Warning -> Medium
            4: 1,  # Information
            5: 1,  # Verbose
        }

        return windows_level_map.get(
            value,
            99
        )

    value = str(value).strip().lower()

    table = {
        "debug": 1,
        "verbose": 1,

        "info": 1,
        "information": 1,
        "informational": 1,

        "low": 2,

        "warn": 3,
        "warning": 3,
        "medium": 3,

        "error": 4,
        "high": 4,

        "critical": 5,

        "fatal": 6,
    }

    return table.get(
        value,
        99
    )

# ************************************************************

def sysmon_network_severity(
    record: dict[str, Any],
) -> str:

    severity_id = (
        sysmon_network_severity_id(record)
    )

    canonical = {
        0: "Unknown",
        1: "Informational",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
        6: "Fatal",
    }

    if severity_id != 99:
        return canonical[severity_id]

    raw = _sysmon_network_raw_severity(
        record
    )

    if raw is None:
        return "Other"

    return str(raw).strip()

# ****************************************************

def sysmon_network_status_id(
    record: dict[str, Any],
) -> int:

    value = _clean_string(
        record.get("Status")
    )

    if value is None:
        return 0

    normalized = value.lower()

    if normalized in {
        "success",
        "successful",
        "succeeded",
        "ok",
        "allowed"
    }:
        return 1

    if normalized in {
        "failure",
        "failed",
        "error",
        "denied",
        "blocked",
        "refused",
        "timeout"
    }:
        return 2

    return 99

# ************************************************************

def sysmon_network_status(
    record: dict[str, Any],
) -> str:

    status_id = (
        sysmon_network_status_id(record)
    )

    if status_id == 0:
        return "Unknown"

    if status_id == 1:
        return "Success"

    if status_id == 2:
        return "Failure"

    value = _clean_string(
        record.get("Status")
    )

    return value or "Other"

# ****************************************************

def sysmon_utc_time(value: Any) -> int | None:
    """Parse Sysmon UtcTime as UTC, independently of the machine timezone."""
    value = _clean_string(value)
    if value is None:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def sysmon_collector_logged_time(record: dict[str, Any]) -> int | None:
    """Only normalize collector receipt time with a known timezone."""
    value = _clean_string(record.get("EventReceivedTime"))
    if value is None:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        offset = record.get("_collector_timezone_offset_minutes")
        if offset is None:
            return None
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=offset)))
    return int(dt.timestamp() * 1000)


def sysmon_network_actor(record: dict[str, Any]) -> dict[str, Any] | None:
    """Host-profile actor; ProcessID is the provider PID, not ProcessId."""
    process: dict[str, Any] = {}
    image = _clean_string(record.get("Image"))
    if image:
        process["name"] = ntpath.basename(image)
        process["path"] = image
    guid = _clean_string(record.get("ProcessGuid"))
    if guid:
        process["uid"] = guid
    pid = _safe_int(record.get("ProcessId"))
    if pid is not None and pid >= 0:
        process["pid"] = pid
    # OCSF process requires a pid, uid, or cpid; preserve image-only data in unmapped.
    if "pid" not in process and "uid" not in process:
        process = {}
    user = windows_domain_user(_clean_string(record.get("User")))
    actor: dict[str, Any] = {}
    if user:
        actor["user"] = user
        if process:
            process["user"] = user.copy()
    if process:
        actor["process"] = process
    return actor or None


def _sysmon_observer_matches(record: dict[str, Any]) -> tuple[bool, bool, bool]:
    """Return source match, destination match, and conflicting evidence."""
    def ip_value(value: Any) -> str | None:
        value = _clean_string(value)
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def host_value(value: Any) -> str | None:
        value = _clean_string(value)
        return value.rstrip(".").casefold() if value else None

    source_match = destination_match = conflict = False
    pairs = [
        (ip_value(record.get("host_ip")), ip_value(record.get("SourceIp")),
         ip_value(record.get("DestinationIp"))),
        (host_value(record.get("Hostname")) or host_value(record.get("Computer")),
         host_value(record.get("SourceHostname")),
         host_value(record.get("DestinationHostname"))),
    ]
    for host, source, destination in pairs:
        if host is None or (source is None and destination is None):
            continue
        source_hit = source is not None and host == source
        destination_hit = destination is not None and host == destination
        source_match |= source_hit
        destination_match |= destination_hit
        conflict |= not source_hit and not destination_hit
    # Different evidence assigning the observer to opposite endpoints conflicts,
    # except when an individual comparison actually matches both (loopback).
    both_in_one = any(h is not None and h == a == b for h, a, b in pairs)
    conflict |= source_match and destination_match and not both_in_one
    return source_match, destination_match, conflict


def sysmon_network_device(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    result: dict[str, Any] = {}

    hostname = _clean_string(
        record.get("Hostname")
    ) or _clean_string(
        record.get("Computer")
    )

    host_ip = _clean_string(
        record.get("host_ip")
    )

    if hostname:
        result["hostname"] = hostname

    if host_ip:
        result["ip"] = host_ip

    if result:
        result.update({"type_id": 0, "type": "Unknown"})
    return result or None


# *************************************************************

def _infer_ip_version(
    record: dict[str, Any],
) -> int:

    source_ipv6 = _parse_sysmon_bool(
        record.get("SourceIsIpv6")
    )

    destination_ipv6 = _parse_sysmon_bool(
        record.get("DestinationIsIpv6")
    )

    if (
        source_ipv6 is True
        or destination_ipv6 is True
    ):
        return 6

    if (
        source_ipv6 is False
        and destination_ipv6 is False
    ):
        return 4

    versions: set[int] = set()

    for field in (
        "SourceIp",
        "DestinationIp",
    ):
        value = _clean_string(
            record.get(field)
        )

        if not value:
            continue

        try:
            versions.add(
                ipaddress.ip_address(value).version
            )
        except ValueError:
            continue

    if len(versions) == 1:
        return next(iter(versions))

    return 0


# ******************************************************

def sysmon_source_endpoint(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    endpoint: dict[str, Any] = {}

    hostname = _clean_string(
        record.get("SourceHostname")
    )

    ip = _clean_string(
        record.get("SourceIp")
    )

    port = _safe_int(
        record.get("SourcePort")
    )


    if hostname:
        endpoint["hostname"] = hostname

    if ip:
        endpoint["ip"] = ip

    if port is not None and 0 <= port <= 65535:
        endpoint["port"] = port


    # A port alone does not satisfy the OCSF endpoint identity constraint.
    return endpoint if hostname or ip else None

# ***************************************************

def sysmon_destination_endpoint(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    endpoint: dict[str, Any] = {}

    hostname = _clean_string(
        record.get("DestinationHostname")
    )

    ip = _clean_string(
        record.get("DestinationIp")
    )

    port = _safe_int(
        record.get("DestinationPort")
    )


    if hostname:
        endpoint["hostname"] = hostname

    if ip:
        endpoint["ip"] = ip

    if port is not None and 0 <= port <= 65535:
        endpoint["port"] = port


    # A port alone does not satisfy the OCSF endpoint identity constraint.
    return endpoint if hostname or ip else None

# ****************************************************
def sysmon_windows_resource(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        return None

    if event_id == 9:

        name = record.get("Device")

        if not name:
            return None

        return {
            "name": str(name),
            "type_id": 4,
            "type": "Device",
        }

    if event_id in {17, 18}:

        name = record.get("PipeName")

        if not name:
            return None

        return {
            "name": str(name),
            "type_id": 99,
            "type": "Named Pipe",
        }

    if event_id in {19, 20, 21}:

        name = (
            record.get("Name")
            or record.get("Filter")
            or record.get("Consumer")
            or "WMI Resource"
        )

        details = (
            record.get("Query")
            or record.get("Destination")
        )

        result = {
            "name": str(name),
            "type_id": 19,
            "type": "WmiGuid",
        }

        if details:
            result["details"] = str(details)

        return result

    return None


# ***********************************************
def sysmon_module(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    path = record.get("ImageLoaded")

    if not path:
        return None

    file_object: dict[str, Any] = {
        "name": windows_basename(path),
        "path": str(path),
        "type_id": 1,
        "type": "Regular File",
    }

    hashes = (
        sysmon_hashes_to_ocsf_fingerprints(
            record.get("Hashes")
        )
    )

    if hashes:
        file_object["hashes"] = hashes

    return {
        "file": file_object,
        "load_type_id": 1,
        "load_type": "Standard"
    }


# ****************************************************************
def sysmon_driver(
    record: dict[str, Any],
) -> dict[str, Any] | None:

    path = (
        record.get("ImageLoaded")
        or record.get("Image")
    )

    if not path:
        return None

    file_object: dict[str, Any] = {
        "name": windows_basename(path),
        "path": str(path),
        "type_id": 1,
        "type": "Regular File",
    }

    hashes = (
        sysmon_hashes_to_ocsf_fingerprints(
            record.get("Hashes")
        )
    )

    if hashes:
        file_object["hashes"] = hashes

    return {
        "file": file_object
    }


# ***************************************************************
def sysmon_service(record: dict[str, Any]) -> dict[str, Any]:
    """Required Windows service object; native ID 4 describes Sysmon's service."""
    name = _clean_string(record.get("ServiceName"))
    result: dict[str, Any] = {"name": name or "Sysmon"}
    # Sysmon is a user-mode Windows service, accompanied by a separate driver.
    # Unknown is used outside its documented service-state event.
    category_id = 2 if _sysmon_event_id(record) == 4 else 0
    result.update({"service_category_id": category_id,
                   "service_category": {0: "Unknown", 2: "User Mode"}[category_id]})
    # Populate optional properties only from explicit service-specific fields.
    for source, target in {
        "ServiceCommandLine": "cmd_line",
        "ServiceStartName": "service_start_name",
        "ServiceLoadOrderGroup": "load_order_group",
    }.items():
        value = _clean_string(record.get(source))
        if value is not None:
            result[target] = value
    return result


# *******************************************************
def sysmon_service_activity_name(record: dict[str, Any]) -> str:
    activity = sysmon_service_activity_id(record)
    if activity == 99:
        return _clean_string(record.get("State")) or "Other"
    return {0: "Unknown", 3: "Start", 4: "Stop"}[activity]


# ***********************************************************************
def sysmon_service_activity_id(record: dict[str, Any]) -> int:
    """Sysmon ID 4 reports state changes, not service installation/deletion."""
    state = _clean_string(record.get("State"))
    if state is None:
        return 0
    # Exact matching avoids treating 'not started' or 'restart failed' as Start.
    return {"started": 3, "start": 3, "running": 3,
            "stopped": 4, "stop": 4}.get(state.casefold(), 99)


# ******************************************************************

def sysmon_service_type_uid(record: dict[str, Any]) -> int:
    # Calculate in the custom stage together with activity_id.
    return 201004 * 100 + sysmon_service_activity_id(record)


def sysmon_service_type_name(record: dict[str, Any]) -> str:
    return "Windows Service Activity: " + sysmon_service_activity_name(record)


def sysmon_service_severity_id(record: dict[str, Any]) -> int:
    if _sysmon_network_raw_severity(record) is None:
        return 1 if _sysmon_event_id(record) == 4 else 0
    return sysmon_network_severity_id(record)


def sysmon_service_severity(record: dict[str, Any]) -> str:
    severity_id = sysmon_service_severity_id(record)
    captions = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
                4: "High", 5: "Critical", 6: "Fatal"}
    return captions.get(severity_id, str(_sysmon_network_raw_severity(record)).strip())


def sysmon_service_product_version(record: dict[str, Any]) -> str | None:
    # Native ID 4 Version is the Sysmon binary version; a collector may instead
    # expose the numeric event-header version under the same flat key.
    value = _clean_string(record.get("SysmonVersion") or record.get("Version"))
    return value if value and re.fullmatch(r"\d+(?:\.\d+)+", value) else None


def sysmon_service_actor(record: dict[str, Any]) -> dict[str, Any] | None:
    """Use explicit initiator enrichment only; provider PID/account is not proof."""
    return sysmon_network_actor({
        "ProcessId": record.get("ActorProcessId"),
        "ProcessGuid": record.get("ActorProcessGuid"),
        "Image": record.get("ActorImage"),
        "User": record.get("ActorUser"),
    })


def sysmon_error_message(record: dict[str, Any]) -> str | None:
    return _clean_string(record.get("Message")) or _clean_string(record.get("Description"))


def sysmon_connection_info(
    record: dict[str, Any],
) -> dict[str, Any]:

    result: dict[str, Any] = {
        # Required by OCSF network_connection_info.
        # Sysmon alone does not tell us
        # Internal/External/Lateral boundary direction.
        "direction_id": 0,
        "direction": "Unknown",
    }

    protocol = _clean_string(
        record.get("Protocol")
    )

    if protocol:
        normalized = protocol.lower()

        result["protocol_name"] = normalized

        protocol_num = _PROTOCOL_NUMBERS.get(
            normalized
        )

        if protocol_num is not None:
            result["protocol_num"] = protocol_num

    ip_version = _infer_ip_version(record)

    result["protocol_ver_id"] = ip_version

    if ip_version == 4:
        result["protocol_ver"] = (
            "Internet Protocol version 4 (IPv4)"
        )

    elif ip_version == 6:
        result["protocol_ver"] = (
            "Internet Protocol version 6 (IPv6)"
        )

    else:
        result["protocol_ver"] = "Unknown"

    return result

# *********************************************************************

def sysmon_network_initiator_id(record: dict[str, Any]) -> int:
    if _sysmon_event_id(record) != 3:
        return 0
    source, destination, conflict = _sysmon_observer_matches(record)
    initiated = _parse_sysmon_bool(record.get("Initiated"))
    if conflict or source == destination or initiated is None:
        return 0
    # Initiated describes the local process. Relate that host to the endpoints.
    if source:
        return 1 if initiated else 2
    return 2 if initiated else 1

# *******************************************************************

def sysmon_network_initiator(record: dict[str, Any]) -> str:
    return {0: "Unknown", 1: "Source Endpoint", 2: "Destination Endpoint"}[
        sysmon_network_initiator_id(record)
    ]

# ***********************************************************

def sysmon_network_observation_point_id(record: dict[str, Any]) -> int:
    source, destination, conflict = _sysmon_observer_matches(record)
    if conflict:
        return 0
    if source and destination:
        return 4
    if source:
        return 1
    if destination:
        return 2
    # Initiated alone cannot establish where the observer sits in the mapped
    # endpoints. Keep Unknown when direct host evidence is unavailable.
    return 0

# ********************************************************

def sysmon_network_observation_point(
    record: dict[str, Any],
) -> str:

    observation_id = (
        sysmon_network_observation_point_id(
            record
        )
    )

    return {
        0: "Unknown",
        1: "Source",
        2: "Destination",
        3: "Neither",
        4: "Both",
        99: "Other",
    }[observation_id]


# **********************************************************************************************
def multi_antivirus_unmapped(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Preserve Multi Anti Virus source-specific fields that do not
    currently have a reliable canonical OCSF mapping.
    """

    output: dict[str, Any] = {}

    explicit_fields = {
        "pri",
        "vendor",
        "level",
        "Scan_Status",
        "detection_rate",
        "status_antiviruses",
        "Sandbox_Score",
    }

    prefixes = (
        "status_",
        "detail_",
        "infected_",
        "error_",
        "version_",
        "update_date_",
        "updated_date_",
    )

    for key, value in record.items():

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        if key in explicit_fields or key.startswith(prefixes):
            output[key] = value

    return output or None
# ***************************************************************************************
def multi_antivirus_is_alert(
    record: dict[str, Any],
) -> bool:
    """
    Determine whether this finding is an alertable signal.
    """

    if record.get("Infected IP"):
        return True

    level = record.get("level")

    if isinstance(level, str):
        if level.strip().upper() in {
            "WARNING",
            "WARN",
            "ERROR",
            "CRITICAL",
            "FATAL",
        }:
            return True

    return False
# *******************************************************************************************************
def multi_antivirus_severity(
    record: dict[str, Any],
) -> str:
    """
    Return the OCSF severity label.
    """

    level = record.get("level")

    if level is None:
        return "Unknown"

    level = str(level).strip()

    if not level:
        return "Unknown"

    return level
# ****************************************************************************************************
def multi_antivirus_severity_id(
    record: dict[str, Any],
) -> int:
    """
    Normalize antivirus finding severity.

    Missing source severity -> Unknown.
    Source-specific severity -> Other.
    """

    level = record.get("level")

    if level is None:
        return 0

    if isinstance(level, str) and not level.strip():
        return 0

    return 99
# **********************************************************************************************
def multi_antivirus_finding_title(
    record: dict[str, Any],
) -> str:
    """
    Generate a concise OCSF finding title.
    """

    filename = record.get("filename")
    infected_ip = record.get("Infected IP")

    if filename:
        return f"Multi antivirus scan result: {filename}"

    if infected_ip:
        return f"Multi antivirus warning for {infected_ip}"

    return "Multi antivirus finding"
# **********************************************************************************************
def multi_antivirus_scan_info(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Build OCSF malware scan information when the record contains
    actual file scan data.
    """

    filename = record.get("filename")
    scan_time = record.get("Scan_DateTime")

    if not filename and not scan_time:
        return None

    return {
        "name": "Multi Anti Virus File Scan",
        "type_id": 0,
        "type": "Unknown",
    }
# ******************************************************************************************
def multi_antivirus_affected_device(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Build the affected OCSF device from the source's Infected IP field.
    """

    infected_ip = record.get("Infected IP")

    if not infected_ip:
        return None

    return {
        "ip": str(infected_ip),
        "type_id": 0,
        "type": "Unknown",
    }
# ********************************************************************************************
def parse_file_size(value: Any) -> int | None:
    """
    Extract the byte count from values such as:

        1.1 MB (1154775 bytes)
    """

    if value is None:
        return None

    match = re.search(
        r"\((\d+)\s+bytes\)",
        str(value),
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    return None

# ******************************************************************************************
def multi_antivirus_evidences(
    record: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """
    Build OCSF evidence for the file scanned by the antivirus product.
    """

    filename = record.get("filename")
    file_type = record.get("File_Type")
    file_size = record.get("File_Size")
    md5 = record.get("File_MD5")
    sha1 = record.get("File_SHA-1")

    if not any(
        (
            filename,
            file_type,
            file_size,
            md5,
            sha1,
        )
    ):
        return None

    # File.name is required by the OCSF File object.
    if not filename:
        return None

    file_object: dict[str, Any] = {
        "name": str(filename),

        # OCSF Regular File.
        "type_id": 1,
        "type": "Regular File",
    }

    if file_type:
        file_object["desc"] = str(file_type)

    if file_size:
        size = parse_file_size(file_size)

        if size is not None:
            file_object["size"] = size

    hashes: list[dict[str, Any]] = []

    if md5:
        hashes.append(
            {
                "algorithm_id": 1,
                "algorithm": "MD5",
                "value": str(md5),
            }
        )

    if sha1:
        hashes.append(
            {
                "algorithm_id": 2,
                "algorithm": "SHA-1",
                "value": str(sha1),
            }
        )

    if hashes:
        file_object["hashes"] = hashes

    return [
        {
            "file": file_object,
        }
    ]



# **********************************************
def sysmon_event_status_text(
    record: dict[str, Any],
) -> str:

    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        event_id = None

    if event_id in {27, 28}:
        return "Failure"

    status = record.get("Status")

    if status is None:
        return "Success"

    status = str(status).strip()

    return status or "Success"
# ********************************************************************
def sysmon_event_status_id(
    record: dict[str, Any],
) -> int:

    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        event_id = None

    # Sysmon blocked the requested operation.
    if event_id in {27, 28}:
        return 2

    status = record.get("Status")

    if status is None:
        return 1

    if isinstance(status, str) and not status.strip():
        return 1

    return 99



# ************************************************************************************** should be deleted????
def sysmon_status_text(value: Any) -> str:
    """
    No raw Status -> Success
    Raw Status exists -> preserve raw value
    """
    if value is None:
        return "Success"

    if isinstance(value, str) and not value.strip():
        return "Success"

    return str(value)


# ************************************************************** should be deleted???
def sysmon_status_id(value: Any) -> int:
    """
    Map Sysmon status presence to OCSF status_id.

    No status value -> 1
    Status exists   -> 99
    """
    if value is None:
        return 1

    if isinstance(value, str) and not value.strip():
        return 1

    return 99

# ***********************************************************************************************
def sysmon_severity_text(value: Any) -> str | None:
    """
    Convert Sysmon severity to the OCSF severity label.

    INFO -> Informational
    anything else -> Other: <raw value>
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.upper() == "INFO":
        return "Informational"

    return f"Other: {value}"

# *********************************************************************
def to_string(value: Any) -> str | None:
    if value is None:
        return None

    return str(value)


# ---------------------------------------------------------------------------
# SDWAN Embedded syslog IDS alert parsing
# ---------------------------------------------------------------------------

def _parse_syslog_embedded_alert(value: Any) -> dict[str, Any]:
    """
    Extract fields from a JSON-like object embedded inside a syslog message.

    Example input:

        <178>Aug 31 13:30:10 Si-p SyslGen {
            \"gid\":1,
            \"dst_ip\":\"10.12.15.31\",
            ...
        }

    The parser is deliberately tolerant because some received messages may
    contain truncated embedded JSON.

    It extracts every complete key/value pair that is still present.
    """

    if value is None:
        return {}

    text = str(value).strip()

    if not text:
        return {}

    # The JSON payload inside the syslog message may still contain
    # escaped quotation marks.
    text = text.replace('\\"', '"')

    # Ignore the RFC3164/syslog prefix and start from the embedded object.
    object_start = text.find("{")

    if object_start >= 0:
        text = text[object_start:]

    result: dict[str, Any] = {}

    # Supports:
    #
    #   "key":"value"
    #   "key":123
    #   "key":-123
    #   "key":true
    #   "key":false
    #   "key":null
    #
    # It does not require the complete JSON object to be present.
    pattern = re.compile(
        r'"(?P<key>[^"]+)"\s*:\s*'
        r'(?:'
        r'"(?P<string>(?:\\.|[^"])*)"'
        r'|(?P<number>-?\d+(?:\.\d+)?)'
        r'|(?P<boolean>true|false)'
        r'|(?P<null>null)'
        r')',
        re.IGNORECASE,
    )

    for match in pattern.finditer(text):
        key = match.group("key")

        string_value = match.group("string")
        number_value = match.group("number")
        boolean_value = match.group("boolean")
        null_value = match.group("null")

        if string_value is not None:
            value_out: Any = string_value

        elif number_value is not None:
            if "." in number_value:
                value_out = float(number_value)
            else:
                value_out = int(number_value)

        elif boolean_value is not None:
            value_out = boolean_value.lower() == "true"

        elif null_value is not None:
            value_out = None

        else:
            continue

        result[key] = value_out

    return result


# ***************************************************************
def syslog_alert_time(value: Any) -> int | None:
    """
    Extract the embedded @timestamp and convert it to OCSF epoch milliseconds.

    Example:

        2026-08-25T13:28:07.269Z

    becomes:

        1787664487269
    """

    fields = _parse_syslog_embedded_alert(value)

    timestamp = fields.get("@timestamp")

    if timestamp is None:
        return None

    try:
        dt = datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )

        return int(
            dt.astimezone(timezone.utc).timestamp() * 1000
        )

    except (TypeError, ValueError):
        return None
# *******************************************************************
def syslog_alert_classification(value: Any) -> str | None:
    """
    Extract the IDS/IPS classification and use it as the
    OCSF finding title.
    """

    fields = _parse_syslog_embedded_alert(value)

    classification = fields.get("classification")

    if classification is None:
        return None

    classification = str(classification).strip()

    return classification or None

def syslog_alert_description(value: Any) -> str | None:
    """
    Build a short description from GID, SID, and classification.
    """

    fields = _parse_syslog_embedded_alert(value)

    gid = fields.get("gid")
    sid = fields.get("sid")
    classification = fields.get("classification")

    parts: list[str] = []

    if classification:
        parts.append(str(classification))

    signature_parts: list[str] = []

    if gid is not None:
        signature_parts.append(f"GID={gid}")

    if sid is not None:
        signature_parts.append(f"SID={sid}")

    if signature_parts:
        parts.append(
            "Signature " + ", ".join(signature_parts)
        )

    if not parts:
        return None

    return "; ".join(parts)


def syslog_alert_evidences(
    value: Any,
) -> list[dict[str, Any]] | None:
    """
    Convert the embedded IDS network tuple into OCSF evidences.
    """

    fields = _parse_syslog_embedded_alert(value)

    src_ip = fields.get("src_ip")
    src_port = fields.get("src_port")

    dst_ip = fields.get("dst_ip")
    dst_port = fields.get("dst_port")

    evidence: dict[str, Any] = {}

    if src_ip is not None or src_port is not None:

        src_endpoint: dict[str, Any] = {}

        if src_ip:
            src_endpoint["ip"] = str(src_ip)

        if src_port is not None:
            try:
                src_endpoint["port"] = int(src_port)
            except (TypeError, ValueError):
                pass

        if src_endpoint:
            evidence["src_endpoint"] = src_endpoint

    if dst_ip is not None or dst_port is not None:

        dst_endpoint: dict[str, Any] = {}

        if dst_ip:
            dst_endpoint["ip"] = str(dst_ip)

        if dst_port is not None:
            try:
                dst_endpoint["port"] = int(dst_port)
            except (TypeError, ValueError):
                pass

        if dst_endpoint:
            evidence["dst_endpoint"] = dst_endpoint

    if not evidence:
        return None

    return [evidence]

def syslog_alert_original_fields(
    value: Any,
) -> dict[str, Any] | None:
    """
    Preserve source-specific embedded IDS attributes that we do not
    currently claim as canonical OCSF mappings.
    """

    fields = _parse_syslog_embedded_alert(value)

    output: dict[str, Any] = {}

    field_names = (
        "gid",
        "sid",
        "protocol",
        "device",
        "classification",
    )

    for field_name in field_names:

        field_value = fields.get(field_name)

        if field_value is not None:
            output[field_name] = field_value

    return output or None








# ******************************************************************************************************************
# ---------------------------------------------------------------------------
# sysmon  Windows path operations
# ---------------------------------------------------------------------------

def windows_basename(value: Any) -> str | None:
    """
    Extract the final component of a Windows path.

    Example:
        C:\\Windows\\System32\\cmd.exe
        -> cmd.exe
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return ntpath.basename(value)


def windows_dirname(value: Any) -> str | None:
    """
    Extract the directory portion of a Windows path.

    Example:
        C:\\Windows\\System32\\cmd.exe
        -> C:\\Windows\\System32
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    directory = ntpath.dirname(value)

    return directory if directory else None


# ---------------------------------------------------------------------------
# Windows domain\\user transformation
# ---------------------------------------------------------------------------

def windows_domain_user(value: Any) -> dict[str, str] | None:
    """
    Convert a Windows DOMAIN\\USER string into an OCSF user object.

    Example:
        NT AUTHORITY\\SYSTEM

    becomes:

        {
            "name": "SYSTEM",
            "domain": "NT AUTHORITY"
        }

    If no backslash exists, the complete value is treated as the user name.
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if "\\" in value:
        domain, username = value.rsplit("\\", 1)

        result: dict[str, str] = {}

        if domain:
            result["domain"] = domain

        if username:
            result["name"] = username

        return result or None

    return {"name": value}


# ---------------------------------------------------------------------------
# Sysmon hashes -> OCSF fingerprints
# ---------------------------------------------------------------------------

_HASH_ALGORITHMS = {
    "MD5": {
        "algorithm_id": 1,
        "algorithm": "MD5",
    },
    "SHA1": {
        "algorithm_id": 2,
        "algorithm": "SHA-1",
    },
    "SHA-1": {
        "algorithm_id": 2,
        "algorithm": "SHA-1",
    },
    "SHA256": {
        "algorithm_id": 3,
        "algorithm": "SHA-256",
    },
    "SHA-256": {
        "algorithm_id": 3,
        "algorithm": "SHA-256",
    },
    "SHA512": {
        "algorithm_id": 4,
        "algorithm": "SHA-512",
    },
    "SHA-512": {
        "algorithm_id": 4,
        "algorithm": "SHA-512",
    },
    "IMPHASH": {
        "algorithm_id": 18,
        "algorithm": "Imphash",
    },
}


def sysmon_hashes_to_ocsf_fingerprints(value: Any) -> list[dict[str, Any]] | None:
    """
    Convert a Sysmon Hashes string into an OCSF fingerprint array.

    Example input:

        MD5=ABC,SHA256=DEF,IMPHASH=123

    Example output:

        [
            {
                "algorithm_id": 1,
                "algorithm": "MD5",
                "value": "ABC"
            },
            {
                "algorithm_id": 3,
                "algorithm": "SHA-256",
                "value": "DEF"
            },
            {
                "algorithm_id": 18,
                "algorithm": "Imphash",
                "value": "123"
            }
        ]

    Unknown algorithms are preserved using OCSF's "Other" algorithm ID 99.
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    fingerprints: list[dict[str, Any]] = []

    for item in value.split(","):
        item = item.strip()

        if not item or "=" not in item:
            continue

        algorithm_name, hash_value = item.split("=", 1)

        algorithm_name = algorithm_name.strip()
        hash_value = hash_value.strip()

        if not hash_value:
            continue

        normalized = algorithm_name.upper()

        algorithm_info = _HASH_ALGORITHMS.get(normalized)

        if algorithm_info is None:
            fingerprints.append(
                {
                    "algorithm_id": 99,
                    "algorithm": algorithm_name,
                    "value": hash_value,
                }
            )
            continue

        fingerprints.append(
            {
                "algorithm_id": algorithm_info["algorithm_id"],
                "algorithm": algorithm_info["algorithm"],
                "value": hash_value,
            }
        )

    return fingerprints or None










# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


# Temporary placeholders: implement these Sysmon transformations later.

def sysmon_actor(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_actor; omit this field for now."""
    return None


def sysmon_clipboard(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_clipboard; omit this field for now."""
    return None


def sysmon_current_process(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_current_process; omit this field for now."""
    return None


def sysmon_registry_key(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_key; omit this field for now."""
    return None


def sysmon_registry_key_activity_id(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_key_activity_id; omit this field for now."""
    return None


def sysmon_registry_key_activity_name(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_key_activity_name; omit this field for now."""
    return None


def sysmon_registry_value(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_value; omit this field for now."""
    return None


def sysmon_registry_value_activity_id(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_value_activity_id; omit this field for now."""
    return None


def sysmon_registry_value_activity_name(record: dict[str, Any]) -> None:
    """TODO: implement sysmon_registry_value_activity_name; omit this field for now."""
    return None


def sysmon_target_file(record: dict[str, Any]) -> dict[str, Any] | None:
    return _sysmon_target_file(record)


# Sysmon File System Activity (OCSF 1.9.0).
_SYSMON_FILE_ACTIVITIES = {
    # Native FileCreate (11) covers creation AND overwriting; do not guess which.
    2: (6, "Set Attributes"), 11: (99, "FileCreate"), 15: (1, "Create"),
    23: (4, "Delete"), 26: (4, "Delete"), 27: (1, "Create"),
    # Shredding need not be a delete: do not invent the underlying I/O operation.
    28: (99, "FileBlockShredding"), 29: (1, "Create"),
}


def sysmon_file_activity_id(record: dict[str, Any]) -> int:
    event_id = _sysmon_event_id(record)
    if event_id is None:
        return 0
    return _SYSMON_FILE_ACTIVITIES.get(event_id, (99, "Other"))[0]


def sysmon_file_activity_name(record: dict[str, Any]) -> str:
    event_id = _sysmon_event_id(record)
    if event_id is None:
        return "Unknown"
    if event_id in _SYSMON_FILE_ACTIVITIES:
        return _SYSMON_FILE_ACTIVITIES[event_id][1]
    return _clean_string(record.get("Category")) or f"Sysmon Event {event_id}"


def sysmon_file_type_uid(record: dict[str, Any]) -> int:
    return 100100 + sysmon_file_activity_id(record)


def sysmon_file_type_name(record: dict[str, Any]) -> str:
    return "File System Activity: " + sysmon_file_activity_name(record)


def _sysmon_file_severity_pair(record: dict[str, Any]) -> tuple[int, str]:
    captions = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
                4: "High", 5: "Critical", 6: "Fatal"}
    labels = {"debug": 1, "verbose": 1, "info": 1, "information": 1,
              "informational": 1, "low": 2, "warn": 3, "warning": 3,
              "medium": 3, "error": 4, "high": 4, "critical": 5, "fatal": 6}
    for field in ("Severity", "EventType", "Level"):
        value = _clean_string(record.get(field))
        if value is None:
            continue
        severity_id = labels.get(value.casefold())
        if severity_id is None and field == "Level" and value.isdecimal():
            severity_id = {0: 0, 1: 5, 2: 4, 3: 3, 4: 1, 5: 1}.get(int(value))
        if severity_id is None:
            return 99, value
        return severity_id, captions[severity_id]
    return (1, "Informational") if _sysmon_event_id(record) in _SYSMON_FILE_ACTIVITIES else (0, "Unknown")


def sysmon_file_severity_id(record: dict[str, Any]) -> int:
    return _sysmon_file_severity_pair(record)[0]


def sysmon_file_severity(record: dict[str, Any]) -> str:
    return _sysmon_file_severity_pair(record)[1]


def sysmon_file_status_id(record: dict[str, Any]) -> int:
    event_id = _sysmon_event_id(record)
    if event_id in {27, 28}:
        return 2  # Failure of the requested file operation, not of Sysmon.
    if _clean_string(record.get("Status")) is not None:
        return sysmon_network_status_id(record)
    # These native events report an observed change, creation or deletion.
    return 1 if event_id in {2, 11, 15, 23, 26, 29} else 0


def sysmon_file_status(record: dict[str, Any]) -> str:
    status_id = sysmon_file_status_id(record)
    if status_id == 99:
        return _clean_string(record.get("Status")) or "Other"
    return {0: "Unknown", 1: "Success", 2: "Failure"}[status_id]


def sysmon_file_actor(record: dict[str, Any]) -> dict[str, Any] | None:
    """Use the operation's ProcessId/ProcessGuid/User, never provider ProcessID."""
    actor = sysmon_network_actor(record)
    if actor and "process" in actor:
        process = actor["process"]
        image = process.get("path")
        if image and ntpath.basename(image):
            process["file"] = {"path": image, "name": ntpath.basename(image),
                               "type_id": 8, "type": "Executable File"}
        command_line = _clean_string(record.get("CommandLine"))
        if command_line:
            process["cmd_line"] = command_line
    return actor


def _sysmon_target_file(record: dict[str, Any], resulting: bool = False) -> dict[str, Any] | None:
    path = _clean_string(record.get("TargetFilename"))
    if not path or not ntpath.basename(path):
        return None
    event_id = _sysmon_event_id(record)
    executable = event_id in {27, 29}
    # Event 15 describes a named stream; an executable base file does not make
    # its stream executable, and its Hash is the unnamed/base file's hash.
    if event_id != 15:
        executable = _parse_sysmon_bool(record.get("IsExecutable")) is True or executable
    result: dict[str, Any] = {
        "name": ntpath.basename(path), "path": path,
        "type_id": 8 if executable else 1,
        "type": "Executable File" if executable else "Regular File",
    }
    parent = ntpath.dirname(path)
    if parent:
        result["parent_folder"] = parent
    if event_id != 15:
        ext = ntpath.splitext(path)[1].lstrip(".")
        if ext:
            result["ext"] = ext
        hashes = _clean_string(record.get("Hashes")) or _clean_string(record.get("Hash"))
        if hashes:
            fingerprints = sysmon_hashes_to_ocsf_fingerprints(hashes)
            if fingerprints:
                result["hashes"] = fingerprints
    time_field = "PreviousCreationUtcTime" if event_id == 2 and not resulting else "CreationUtcTime"
    created_time = sysmon_utc_time(record.get(time_field))
    if created_time is not None:
        result["created_time"] = created_time
    size = _safe_int(record.get("FileSize"))
    if size is not None and size >= 0:
        result["size"] = size
    if event_id in {23, 26} and sysmon_file_status_id(record) == 1:
        result["is_deleted"] = True
    return result


def sysmon_file_result(record: dict[str, Any]) -> dict[str, Any] | None:
    # Event 2 provides before/after creation timestamps. Other file events do
    # not need a duplicate resulting object merely to add more fields.
    if _sysmon_event_id(record) != 2 or sysmon_file_status_id(record) != 1:
        return None
    if _clean_string(record.get("CreationUtcTime")) is None:
        return None
    return _sysmon_target_file(record, resulting=True)


CUSTOM_OPS = {
    "sysmon_file_activity_id": sysmon_file_activity_id,
    "sysmon_file_activity_name": sysmon_file_activity_name,
    "sysmon_file_type_uid": sysmon_file_type_uid,
    "sysmon_file_type_name": sysmon_file_type_name,
    "sysmon_file_severity_id": sysmon_file_severity_id,
    "sysmon_file_severity": sysmon_file_severity,
    "sysmon_file_status_id": sysmon_file_status_id,
    "sysmon_file_status": sysmon_file_status,
    "sysmon_file_actor": sysmon_file_actor,
    "sysmon_file_result": sysmon_file_result,

    "sysmon_service_type_uid": sysmon_service_type_uid,
    "sysmon_service_type_name": sysmon_service_type_name,
    "sysmon_service_severity_id": sysmon_service_severity_id,
    "sysmon_service_severity": sysmon_service_severity,
    "sysmon_service_product_version": sysmon_service_product_version,
    "sysmon_service_actor": sysmon_service_actor,
    "sysmon_error_message": sysmon_error_message,

    "sysmon_utc_time": sysmon_utc_time,
    "sysmon_collector_logged_time": sysmon_collector_logged_time,
    "sysmon_network_actor": sysmon_network_actor,
    "windows_basename": windows_basename,
    "windows_dirname": windows_dirname,
    "windows_domain_user": windows_domain_user,

    "sysmon_hashes_to_ocsf_fingerprints": (
        sysmon_hashes_to_ocsf_fingerprints
    ),

    "syslog_alert_time": (
        syslog_alert_time
    ),

    "syslog_alert_classification": (
        syslog_alert_classification
    ),

    "syslog_alert_description": (
        syslog_alert_description
    ),

    "syslog_alert_evidences": (
        syslog_alert_evidences
    ),

    "syslog_alert_original_fields": (
        syslog_alert_original_fields
    ),
    "to_string": to_string,
    "sysmon_severity_text": sysmon_severity_text,
    "sysmon_status_id": sysmon_status_id,
    "sysmon_status_text": sysmon_status_text,
}
CUSTOM_OPS.update(
    {
        "multi_antivirus_evidences": multi_antivirus_evidences,
        "multi_antivirus_affected_device": (
            multi_antivirus_affected_device
        ),
        "multi_antivirus_scan_info": multi_antivirus_scan_info,
        "multi_antivirus_finding_title": (
            multi_antivirus_finding_title
        ),
        "multi_antivirus_severity_id": (
            multi_antivirus_severity_id
        ),
        "multi_antivirus_severity": (
            multi_antivirus_severity
        ),
        "multi_antivirus_is_alert": multi_antivirus_is_alert,
        "multi_antivirus_unmapped": multi_antivirus_unmapped,
    }
)


CUSTOM_OPS.update(
    {
        "sysmon_network_activity_name":
            sysmon_network_activity_name,

        "sysmon_network_type_name":
            sysmon_network_type_name,

        "sysmon_network_severity_id":
            sysmon_network_severity_id,

        "sysmon_network_severity":
            sysmon_network_severity,

        "sysmon_network_status_id":
            sysmon_network_status_id,

        "sysmon_network_status":
            sysmon_network_status,

        "sysmon_network_device":
            sysmon_network_device,

        "sysmon_source_endpoint":
            sysmon_source_endpoint,

        "sysmon_destination_endpoint":
            sysmon_destination_endpoint,

        "sysmon_connection_info":
            sysmon_connection_info,

        "sysmon_network_initiator_id":
            sysmon_network_initiator_id,

        "sysmon_network_initiator":
            sysmon_network_initiator,

        "sysmon_network_observation_point_id":
            sysmon_network_observation_point_id,

        "sysmon_network_observation_point":
            sysmon_network_observation_point,
    }
)

# Register additional operations referenced by the Sysmon mapping.
CUSTOM_OPS.update({
    "sysmon_actor": sysmon_actor,
    "sysmon_clipboard": sysmon_clipboard,
    "sysmon_current_process": sysmon_current_process,
    "sysmon_driver": sysmon_driver,
    "sysmon_event_status_id": sysmon_event_status_id,
    "sysmon_event_status_text": sysmon_event_status_text,
    "sysmon_module": sysmon_module,
    "sysmon_registry_key": sysmon_registry_key,
    "sysmon_registry_key_activity_id": sysmon_registry_key_activity_id,
    "sysmon_registry_key_activity_name": sysmon_registry_key_activity_name,
    "sysmon_registry_value": sysmon_registry_value,
    "sysmon_registry_value_activity_id": sysmon_registry_value_activity_id,
    "sysmon_registry_value_activity_name": sysmon_registry_value_activity_name,
    "sysmon_service": sysmon_service,
    "sysmon_service_activity_id": sysmon_service_activity_id,
    "sysmon_service_activity_name": sysmon_service_activity_name,
    "sysmon_target_file": sysmon_target_file,
    "sysmon_windows_resource": sysmon_windows_resource,
})

def apply_custom_op(
    op: dict[str, Any],
    record: dict[str, Any],
) -> Any:
    """
    Execute one custom mapping operation.

    A custom mapping looks like:

        {
            "windows_basename": "$.Image"
        }

    or:

        {
            "sysmon_hashes_to_ocsf_fingerprints": "$.Hashes"
        }
    """
    if len(op) != 1:
        raise ValueError(
            f"Custom operation must contain exactly one operation: {op!r}"
        )

    operation_name, source_path = next(iter(op.items()))

    if operation_name not in CUSTOM_OPS:
        raise ValueError(
            f"Unknown custom operation: {operation_name}"
        )

    if not isinstance(source_path, str) or not source_path.startswith("$"):
        raise ValueError(
            f"Custom operation source must be a JSON path: {op!r}"
        )

    if source_path == "$":
        return CUSTOM_OPS[operation_name](record)

    value = _get_path(record, source_path)
    return CUSTOM_OPS[operation_name](value)


def _get_path(obj: Any, path: str) -> Any:
    """
    Minimal JSON-path resolver for the auxiliary layer.

    Supports paths such as:

        $.Image
        $.ParentImage
        $.Hashes
    """
    parts = path.lstrip("$").lstrip(".").split(".")

    current = obj

    for part in parts:
        if not part:
            continue

        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)

            if index >= len(current):
                return None

            current = current[index]
        else:
            return None

        if current is None:
            return None

    return current

