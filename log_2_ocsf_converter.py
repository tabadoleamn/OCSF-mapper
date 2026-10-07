"""
Two-stage Sysmon -> OCSF conversion.

Stage 1:
    Apply custom transformations from aux_ops.py.

Stage 2:
    Remove custom operations from the full mapping and pass the remaining
    mapping to the standard ocsf-mapper engine.

Stage 3:
    Deep merge the custom OCSF fields and normal OCSF fields.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from typing import Any

from ocsf_mapper import apply_stream
from ocsf_mapper.sinks import JsonlSink

from aux_ops import apply_custom_op


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAPPING_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\my mapping\ghoghnoos.json"
)

INPUT_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\logs\raw logs\ghoghnoos.20260905_151.log"
)

OUTPUT_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\logs\ocsf formatted logs\ghoghnoos.20260905_151_ocsf.log"
)
mapping_file_name = MAPPING_FILE.stem

# ---------------------------------------------------------------------------
# Custom operation names
# ---------------------------------------------------------------------------

CUSTOM_OP_NAMES = {
    "windows_basename",
    "windows_dirname",
    "windows_domain_user",
    "sysmon_hashes_to_ocsf_fingerprints",
    "syslog_alert_time",
    "syslog_alert_classification",
    "syslog_alert_description",
    "syslog_alert_evidences",
    "syslog_alert_original_fields",
    "to_string",
    "sysmon_severity_text",
    "sysmon_status_id",
    "sysmon_status_text",
    "multi_antivirus_evidences",
    "multi_antivirus_affected_device",
    "multi_antivirus_scan_info",
    "multi_antivirus_finding_title",
    "multi_antivirus_severity_id",
    "multi_antivirus_severity",
    "multi_antivirus_is_alert",
    "multi_antivirus_unmapped",
}


# ***********************************************************
def get_sysmon_ocsf_route(
    record: dict[str, Any],
) -> str:
    """
    Determine the OCSF class for a Sysmon record.
    """

    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        return "base_event"

    if event_id in {1, 5, 8, 10, 25}:
        return "process_activity"

    if event_id in {
        2,
        11,
        15,
        23,
        26,
        27,
        28,
        29,
    }:
        return "file_activity"

    if event_id == 3:
        return "network_activity"

    if event_id == 4:
        return "windows_service_activity"

    if event_id == 6:
        return "kernel_extension_activity"

    if event_id == 7:
        return "module_activity"

    if event_id in {
        9,
        17,
        18,
        19,
        20,
        21,
    }:
        return "windows_resource_activity"

    if event_id == 12:
        event_type = str(
            record.get("EventType", "")
        ).lower()

        if "value" in event_type:
            return "registry_value_activity"

        return "registry_key_activity"

    if event_id == 13:
        return "registry_value_activity"

    if event_id == 14:
        event_type = str(
            record.get("EventType", "")
        ).lower()

        if "value" in event_type:
            return "registry_value_activity"

        return "registry_key_activity"

    if event_id == 22:
        return "dns_activity"

    if event_id == 24:
        return "clipboard_activity"

    if event_id == 255:
        return "application_error"

    # Event 16 and unknown/future Sysmon IDs.
    return "base_event"


# *******************************************************************
def remove_null_keys(value: Any) -> Any:
    """
    Recursively remove dictionary keys whose values are null-like.

    Lists are preserved as-is and their contents are not cleaned.
    """

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            # Recursively clean nested dictionaries.
            if isinstance(item, dict):
                item = remove_null_keys(item)

            if item is None:
                continue

            if isinstance(item, str):
                stripped = item.strip().lower()

                if stripped in {"", "null", "none", "nil"}:
                    continue

            cleaned[key] = item

        return cleaned

    return value


def preprocess_record(
    record: dict[str, Any],
) -> dict[str, Any]:

    record = remove_null_keys(record)

    if mapping_file_name == "sysmon_process_full":

        if record.get("OriginalFileName") == "-":
            record.pop("OriginalFileName", None)

        if record.get("ParentCommandLine") == "-":
            record.pop("ParentCommandLine", None)

        if record.get("ParentImage") == "-":
            record.pop("ParentImage", None)

        record["_ocsf_route"] = (
            get_sysmon_ocsf_route(record)
        )

    return record



# ---------------------------------------------------------------------------
# Basic JSON path utilities
# ---------------------------------------------------------------------------

def get_source_value(record: dict[str, Any], path: str) -> Any:
    """
    Resolve a simple JSON path such as $.Image or $.ParentImage.
    """
    if not path.startswith("$"):
        return path

    parts = path.lstrip("$").lstrip(".").split(".")

    current: Any = record

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


def set_nested_value(
    output: dict[str, Any],
    target: str,
    value: Any,
) -> None:
    """
    Set a dotted OCSF target.

    Example:

        process.file.hashes

    becomes:

        {
            "process": {
                "file": {
                    "hashes": value
                }
            }
        }
    """
    if value is None:
        return

    parts = target.split(".")

    current = output

    for part in parts[:-1]:
        current = current.setdefault(part, {})

    current[parts[-1]] = value


# ---------------------------------------------------------------------------
# Detect custom mappings
# ---------------------------------------------------------------------------

def is_custom_mapping(mapping_definition: Any) -> bool:
    """
    Return True if a mapping definition uses one of our auxiliary operations.
    """
    if not isinstance(mapping_definition, dict):
        return False

    return any(
        operation in CUSTOM_OP_NAMES
        for operation in mapping_definition
    )


# ---------------------------------------------------------------------------
# Build custom OCSF event
# ---------------------------------------------------------------------------

def apply_custom_mappings(
    config: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    """
    Apply only custom operations from the full mapping.
    """
    output: dict[str, Any] = {}

     
    if mapping_file_name=="sysmon_process_full":
        process_mapping = (
            config["classes"]
            ["process_activity"]
            ["mapping"]
        )
    elif mapping_file_name=="ghoghnoos":   
        process_mapping = (
            config["classes"]
            ["detection_finding"]
            ["mapping"]
        )
    elif mapping_file_name == "sdwan_ids_syslog_alert":
        process_mapping = (
            config["classes"]
            ["detection_finding"]
            ["mapping"]
        )                

    for target, operation in process_mapping.items():

        if not is_custom_mapping(operation):
            continue

        value = apply_custom_op(operation, record)

        set_nested_value(
            output,
            target,
            value,
        )

    return output


# ---------------------------------------------------------------------------
# Remove custom mappings
# ---------------------------------------------------------------------------

def remove_custom_mappings(
    config: dict[str, Any],
) -> dict[str, Any]:
    """
    Create a copy of the full mapping with all custom operations removed.

    The returned mapping is safe to pass to ocsf-mapper because it contains
    only operations supported by the repository's normal ops.py.
    """
    normal_config = copy.deepcopy(config)




    if mapping_file_name=="sysmon_process_full":
        process_mapping = (
            normal_config["classes"]
            ["process_activity"]
            ["mapping"]
        )
    elif mapping_file_name=="ghoghnoos":   
        process_mapping = (
            normal_config["classes"]
            ["detection_finding"]
            ["mapping"]
        )        
        
        



    targets_to_remove = [
        target
        for target, operation in process_mapping.items()
        if is_custom_mapping(operation)
    ]

    for target in targets_to_remove:
        del process_mapping[target]

    return normal_config


# ---------------------------------------------------------------------------
# Deep merge
# ---------------------------------------------------------------------------

def deep_merge(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    """
    Recursively merge two dictionaries.

    Nested dictionaries are merged instead of replaced.

    Example:

        left:
            {
                "process": {
                    "name": "Bak.exe"
                }
            }

        right:
            {
                "process": {
                    "pid": 3552
                }
            }

        result:
            {
                "process": {
                    "name": "Bak.exe",
                    "pid": 3552
                }
            }
    """
    result = copy.deepcopy(left)

    for key, right_value in right.items():

        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(right_value, dict)
        ):
            result[key] = deep_merge(
                result[key],
                right_value,
            )

        else:
            result[key] = copy.deepcopy(right_value)

    return result


# ---------------------------------------------------------------------------
# Create temporary mapping file
# ---------------------------------------------------------------------------

def create_temporary_mapping(
    full_config: dict[str, Any],
) -> Path:
    """
    Create a temporary JSON mapping containing only standard ocsf-mapper ops.
    """
    normal_config = remove_custom_mappings(full_config)

    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="sysmon_process_normal_",
        delete=False,
        encoding="utf-8",
    )

    with temp_file:
        json.dump(
            normal_config,
            temp_file,
            indent=2,
        )

    return Path(temp_file.name)


# ---------------------------------------------------------------------------
# Main conversion
# ---------------------------------------------------------------------------

def convert_sysmon() -> None:
    """
    Convert the input Sysmon JSONL file into OCSF JSONL.
    """

    # ---------------------------------------------------------
    # Load the full mapping
    # ---------------------------------------------------------

    with MAPPING_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        full_config = json.load(file)

    # ---------------------------------------------------------
    # Create a temporary mapping containing only normal ops
    # ---------------------------------------------------------

    temporary_mapping = create_temporary_mapping(
        full_config
    )

    print(
        f"Temporary normal mapping created at:\n"
        f"{temporary_mapping}"
    )

    try:

        # -----------------------------------------------------
        # Read raw Sysmon events
        # -----------------------------------------------------

        with INPUT_FILE.open(
            "r",
            encoding="utf-8",
        ) as input_file:

            raw_lines = [
                line.strip()
                for line in input_file
                if line.strip()
            ]

        # -----------------------------------------------------
        # Convert each event
        # -----------------------------------------------------

        final_events: list[dict[str, Any]] = []

        for line_number, line in enumerate(
            raw_lines,
            start=1,
        ):

            try:
                record = json.loads(line)
                record = preprocess_record(record)

            except json.JSONDecodeError as exc:
                print(
                    f"Skipping invalid JSON at line "
                    f"{line_number}: {exc}"
                )
                continue

            # -------------------------------------------------
            # Stage 1: custom operations
            # -------------------------------------------------

            custom_event = apply_custom_mappings(
                full_config,
                record,
            )

            # -------------------------------------------------
            # Stage 2: standard ocsf-mapper operations
            # -------------------------------------------------

            # The mapper expects a stream of JSON records.
            #
            # Instead of creating a separate input file for each
            # event, use a one-line in-memory stream.

            import io

            normal_input = io.StringIO(
                json.dumps(record) + "\n"
            )

            normal_events = list(
                apply_stream(
                    json.load(
                        temporary_mapping.open(
                            "r",
                            encoding="utf-8",
                        )
                    ),
                    normal_input,
                )
            )

            if not normal_events:
                print(
                    f"No OCSF event generated for line "
                    f"{line_number}"
                )
                continue

            normal_event = normal_events[0]

            # -------------------------------------------------
            # Stage 3: deep merge
            # -------------------------------------------------

            final_event = deep_merge(
                normal_event,
                custom_event,
            )

            final_events.append(
                final_event
            )

        # -----------------------------------------------------
        # Write final OCSF JSONL
        # -----------------------------------------------------

        with JsonlSink(
            str(OUTPUT_FILE)
        ) as output:

            output.write_many(
                final_events
            )

    finally:

        # -----------------------------------------------------
        # Delete temporary mapping
        # -----------------------------------------------------

        temporary_mapping.unlink(
            missing_ok=True
        )

    print("Conversion completed.")
    print(
        f"Output saved to:\n{OUTPUT_FILE}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    convert_sysmon()

   