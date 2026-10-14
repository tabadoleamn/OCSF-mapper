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

from aux_ops import CUSTOM_OPS, apply_custom_op


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAPPING_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\mappings\sysmon.json"
)

INPUT_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\raw & ocsf logs\raw logs\windows_20260906_0.log"
)

OUTPUT_FILE = Path(
    r"C:\Users\kooshkestani_m\Desktop\projects\agentic\raw & ocsf logs\ocsf formatted logs\windows_20260906_0_ocsf.log"
)
mapping_file_name = MAPPING_FILE.stem

# ---------------------------------------------------------------------------
# Custom operation names
# ---------------------------------------------------------------------------

# Set only after confirming the collector's timezone. For UTC+03:30 use 210.
# None omits timezone-less receipt timestamps instead of guessing.
COLLECTOR_TIMEZONE_OFFSET_MINUTES: int | None = 210

CUSTOM_OP_NAMES = set(CUSTOM_OPS)

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

    if event_id == 13:
        return "registry_value_activity"

    if event_id in {12, 14}:
        # Collector EventType may be INFO; use native operation evidence only.
        event_data = record.get("EventData")
        nested_type = event_data.get("EventType") if isinstance(event_data, dict) else None
        candidates = [record.get("SysmonEventType"), nested_type, record.get("EventType")]
        key_ops = {12: {"createkey", "deletekey"}, 14: {"renamekey"}}
        value_ops = {12: {"createvalue", "deletevalue"}, 14: {"renamevalue"}}
        routes = set()
        for value in candidates:
            operation = str(value or "").strip().casefold()
            if operation in key_ops[event_id]:
                routes.add("registry_key_activity")
            if operation in value_ops[event_id]:
                routes.add("registry_value_activity")
        # Missing or conflicting subtype: preserve the event without guessing.
        return next(iter(routes)) if len(routes) == 1 else "base_event"

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

# *******************************************************************************


def replace_dash_with_null(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: replace_dash_with_null(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [replace_dash_with_null(item) for item in value]

    if isinstance(value, str) and value.strip() == "-":
        return None

    return value


# ***********************************************************

def preprocess_record(
    record: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    record = replace_dash_with_null(record)
    record = remove_null_keys(record)

    if config.get("source_name") == "sysmon_process":
        offset = COLLECTOR_TIMEZONE_OFFSET_MINUTES
        if offset is not None and (
            isinstance(offset, bool) or not isinstance(offset, int)
            or not -1080 <= offset <= 1080
        ):
            raise ValueError("Collector timezone offset must be integer minutes (-1080..1080)")
        record["_collector_timezone_offset_minutes"] = offset
        record["_ocsf_route"] = get_sysmon_ocsf_route(record)

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


class SourceTrackingRecord(dict):
    """Track top-level source keys read by an auxiliary mapping function.

    Passing the whole record as '$' does not consume it. Reading a nested
    object consumes its top-level source key, as requested for raw-log keys.
    Use this wrapper only during mapping, never during JSON serialization.
    """

    def __init__(self, record: dict[str, Any], used_keys: set[str]) -> None:
        super().__init__(record)
        self.used_keys = used_keys

    def _mark(self, key: Any) -> None:
        if isinstance(key, str):
            self.used_keys.add(key)

    def __getitem__(self, key: Any) -> Any:
        self._mark(key)
        return super().__getitem__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        self._mark(key)
        return super().get(key, default)

    def __contains__(self, key: Any) -> bool:
        self._mark(key)
        return super().__contains__(key)

    def __iter__(self):
        self.used_keys.update(super().keys())
        return super().__iter__()

    def keys(self):
        self.used_keys.update(super().keys())
        return super().keys()

    def items(self):
        self.used_keys.update(super().keys())
        return super().items()

    def values(self):
        self.used_keys.update(super().keys())
        return super().values()

    def copy(self):
        self.used_keys.update(super().keys())
        return dict(super().items())


def collect_standard_source_keys(
    operation: dict[str, Any],
    record: dict[str, Any],
    used_keys: set[str],
    local_names: frozenset[str] = frozenset(),
) -> None:
    """Track the source dependencies of the supplied ops.py DSL.

    Match its dispatch precedence. Constants, lookup-table values, defaults,
    raw payload capture, and expr arithmetic over OCSF fields are not inputs.
    for_each aliases are local names, not raw-log source keys.
    """
    if "const" in operation:
        return
    if "path" in operation:
        selector = operation["path"]
    elif "group" in operation:
        return  # Regex groups are parser metadata, not JSON source keys.
    elif operation.get("raw"):
        return
    else:
        selector = None
        for kind in ("lookup", "time", "range", "int", "bool"):
            if kind in operation:
                selector = operation[kind]
                break
        else:
            if "expr" in operation:
                return
            if "for_each" in operation:
                selector = operation["for_each"]
            else:
                raise ValueError(f"Source tracking does not support operation: {operation!r}")

    if isinstance(selector, str) and ("path" in operation or selector.startswith("$")):
        parts = selector.lstrip("$").lstrip(".").split(".")
        root = parts[0]
        if root and root not in local_names:
            used_keys.add(root)
        elif not root:
            used_keys.update(key for key in record if key not in local_names)

    # Only traverse sub-mappings if the actual loop would execute. Follow the
    # same source resolution as ops.py, including literal array inputs.
    if "for_each" in operation and not any(
        k in operation for k in ("path", "lookup", "time", "range", "int", "bool", "expr")
    ):
        items = get_source_value(record, selector) if isinstance(selector, str) else selector
        if not isinstance(items, list) or not items:
            return
        alias = operation.get("as", "item")
        for item in items:
            sub_record = dict(record)
            sub_record[alias] = item
            for sub_operation in operation.get("map", {}).values():
                collect_standard_source_keys(
                    sub_operation, sub_record, used_keys, local_names | {alias}
                )


def collect_normal_mapping_source_keys(
    config: dict[str, Any],
    record: dict[str, Any],
    used_keys: set[str],
) -> None:
    """Inspect only the class selected for this event, after standard mapping."""
    if config.get("source_name") != "sysmon_process":
        return
    block = config.get("classes", {}).get(record.get("_ocsf_route", "base_event"), {})
    for target, operation in block.get("mapping", {}).items():
        if target == "raw_data" or target == "unmapped" or target.startswith("unmapped."):
            continue
        if not is_custom_mapping(operation):
            collect_standard_source_keys(operation, record, used_keys)


def add_unmapped_source_fields(
    event: dict[str, Any],
    original_record: dict[str, Any],
    used_keys: set[str],
) -> None:
    """Preserve untouched input fields with original names and values."""
    remaining = {
        key: copy.deepcopy(value)
        for key, value in original_record.items()
        if key not in used_keys
    }
    if remaining:
        event["unmapped"] = remaining
    else:
        event.pop("unmapped", None)


# ---------------------------------------------------------------------------
# Build custom OCSF event
# ---------------------------------------------------------------------------

def apply_custom_mappings(
    config: dict[str, Any],
    record: dict[str, Any],
    used_source_keys: set[str] | None = None,
) -> dict[str, Any]:

    output: dict[str, Any] = {}

    if config.get("source_name") == "sysmon_process":

        class_name = record.get(
            "_ocsf_route",
            "base_event",
        )

        class_config = (
            config
            .get("classes", {})
            .get(class_name, {})
        )

        class_mapping = class_config.get(
            "mapping",
            {}
        )

    elif mapping_file_name in {
        "ghoghnoos",
        "sdwan_ids_syslog_alert",
    }:
        class_mapping = (
            config["classes"]
            ["detection_finding"]
            ["mapping"]
        )

    else:
        return output

    for target, operation in (
        class_mapping.items()
    ):

        if not is_custom_mapping(operation):
            continue

        # Exclude passthrough destinations from semantic source consumption.
        track = (used_source_keys is not None and target != "raw_data"
                 and target != "unmapped" and not target.startswith("unmapped."))
        mapping_record = SourceTrackingRecord(record, used_source_keys) if track else record
        value = apply_custom_op(operation, mapping_record)

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

    normal_config = copy.deepcopy(config)

    classes = normal_config.get(
        "classes",
        {}
    )

    for class_config in classes.values():

        class_mapping = class_config.get(
            "mapping",
            {}
        )

        targets_to_remove = [
            target
            for target, operation
            in class_mapping.items()
            if is_custom_mapping(operation)
        ]

        for target in targets_to_remove:
            del class_mapping[target]

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
                line.rstrip("\r\n")
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
                original_record = json.loads(line)
                if not isinstance(original_record, dict):
                    raise ValueError(f"Expected a JSON object at line {line_number}")
                record = preprocess_record(
                    original_record,
                    full_config,
                )

            except json.JSONDecodeError as exc:
                print(
                    f"Skipping invalid JSON at line "
                    f"{line_number}: {exc}"
                )
                continue

            # -------------------------------------------------
            # Stage 1: custom operations
            # -------------------------------------------------

            used_source_keys: set[str] = set()
            custom_event = apply_custom_mappings(
                full_config,
                record,
                used_source_keys,
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
            collect_normal_mapping_source_keys(full_config, record, used_source_keys)

            # -------------------------------------------------
            # Stage 3: deep merge
            # -------------------------------------------------

            final_event = deep_merge(
                normal_event,
                custom_event,
            )

            if full_config.get("source_name") == "sysmon_process":
                add_unmapped_source_fields(final_event, original_record, used_source_keys)

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

   