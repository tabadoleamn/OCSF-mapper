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
from datetime import datetime, timezone
import re






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
def sysmon_service(
    record: dict[str, Any],
) -> dict[str, Any]:

    return {
        "name": "Sysmon",
        "service_category_id": 0
    }


# *******************************************************
def sysmon_service_activity_name(
    record: dict[str, Any],
) -> str:

    activity_id = sysmon_service_activity_id(
        record
    )

    return {
        3: "Start",
        4: "Stop",
    }.get(
        activity_id,
        "Other",
    )


# ***********************************************************************
def sysmon_service_activity_id(
    record: dict[str, Any],
) -> int:

    state = str(
        record.get("State", "")
    ).strip().lower()

    if "start" in state:
        return 3

    if "stop" in state:
        return 4

    return 99

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

CUSTOM_OPS = {
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

