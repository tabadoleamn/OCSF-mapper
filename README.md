# OCSF Mapper

**OCSF Mapper** is a log parsing, normalization, and mapping engine for transforming security telemetry from heterogeneous sources into events compliant with the [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf).

The project is developed as part of **AgenticSOC** and provides a common normalization layer for security events collected from endpoints, operating systems, network security products, and other telemetry sources.

> **Project Status:** Early development. Initial work focuses on Microsoft Sysmon telemetry.

## Overview

Security products and telemetry sources produce events using different formats, field names, structures, and semantics. OCSF Mapper provides a common processing pipeline for converting these source-specific events into a consistent OCSF representation.

The intended processing flow is:

```text
Raw Security Event
        │
        ▼
     Parser
        │
        ▼
   Normalizer
        │
        ▼
   Classifier
        │
        ▼
      Mapper
        │
        ▼
 OCSF Validation
        │
        ▼
   OCSF Event
```

The project aims to keep source parsing, normalization, OCSF mapping, and schema validation separate so that additional telemetry sources can be introduced without redesigning the core mapping engine.

## Goals

OCSF Mapper is intended to provide:

- Parsing of security telemetry from multiple sources.
- Normalization of source-specific fields and data types.
- Classification of source events into appropriate OCSF event classes.
- Mapping of native fields to OCSF attributes.
- Validation of generated events against a defined OCSF schema version.
- Preservation of useful source-specific information when no appropriate OCSF attribute exists.
- Reproducible mappings backed by raw input and expected OCSF output samples.
- A common normalization layer for AgenticSOC security analytics.

## Supported Sources

| Source | Platform | Status |
|---|---|---|
| Microsoft Sysmon | Windows | 🚧 In development |
| Windows Event Log | Windows | Planned |
| Linux Audit / auditd | Linux | Planned |
| Suricata | Network | Planned |
| Zeek | Network | Planned |
| Cloud telemetry | Cloud | Planned |

Support will be introduced incrementally. A source is considered supported only when its mappings and associated validation tests are included in the repository.

## Initial Sysmon Support

The first implementation target is:

```text
Microsoft Sysmon
       │
       ▼
 Parse Native Event
       │
       ▼
 Normalize Fields
       │
       ▼
Determine OCSF Event Class
       │
       ▼
 Map OCSF Attributes
       │
       ▼
Validate Against OCSF Schema
       │
       ▼
     OCSF Event
```

Different Sysmon Event IDs represent different types of security activity and therefore may map to different OCSF event classes.

For example:

```text
Sysmon Event ID 1
Process Creation
        │
        ▼
OCSF Process Activity
```

The mapping is based on the semantics of the source event rather than simply renaming source fields.

## Architecture

OCSF Mapper is designed around several independent processing stages.

### Parser

The parser understands the native representation of a telemetry source and extracts its fields.

It is responsible for source syntax, not OCSF semantics.

### Normalizer

The normalization layer converts source-specific representations into consistent internal values.

Examples include:

- timestamps;
- process identifiers;
- IP addresses and ports;
- usernames;
- file paths;
- hashes;
- host information;
- protocol identifiers.

### Classifier

The classifier determines the appropriate OCSF event class and activity for an incoming source event.

### Mapper

The mapper transforms normalized source fields into OCSF attributes according to the mapping definition for the event.

Conceptually:

```text
Source Field
     │
     ├── optional transformation
     │
     ▼
OCSF Attribute
```

### Validator

Generated events are validated against the OCSF schema version targeted by the corresponding mapping.

Invalid events should not silently be treated as successfully mapped OCSF events.

## Mapping Philosophy

Mappings should be declarative where practical rather than embedding every source-specific field relationship directly into application code.

A mapping conceptually describes:

```text
Source
   +
Event Type
   +
Field Mapping
   +
Transformations
   +
OCSF Class / Activity
   =
OCSF Event
```

For example:

```text
Sysmon.Image
        │
        ▼
Normalization / Transformation
        │
        ▼
OCSF process attribute
```

Each supported mapping should be accompanied by test data containing both the source event and its expected OCSF representation.

```text
Raw Input
    +
Mapping
    +
Expected OCSF Output
```

This makes mappings reviewable, testable, and reproducible.

## OCSF Versioning

OCSF mappings must target an explicit OCSF schema version.

Mappings should not implicitly depend on the latest available OCSF schema because changes between schema versions can affect event classes, attributes, requirements, and semantics.

The intended structure is:

```text
schemas/
└── ocsf/
    └── <version>/
```

The OCSF version supported by each mapping will be documented as implementation progresses.

## Proposed Repository Structure

```text
OCSF-mapper/
│
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
│
├── docs/
│   ├── architecture.md
│   ├── mapping-guide.md
│   └── supported-sources.md
│
├── mappings/
│   ├── windows/
│   │   ├── sysmon/
│   │   └── eventlog/
│   ├── linux/
│   ├── network/
│   └── cloud/
│
├── schemas/
│   └── ocsf/
│
├── testdata/
│   ├── windows/
│   ├── linux/
│   ├── network/
│   └── cloud/
│
├── tests/
│
└── .github/
    └── workflows/
```

This structure is expected to evolve as the implementation matures.

## Example

A simplified Sysmon process creation event may contain fields such as:

```json
{
  "EventID": 1,
  "UtcTime": "2026-10-07T10:00:00Z",
  "ProcessId": 1234,
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "User": "NT AUTHORITY\\SYSTEM"
}
```

OCSF Mapper determines the appropriate OCSF class and maps the source attributes into the corresponding OCSF objects and attributes.

The exact generated structure depends on the OCSF schema version targeted by the mapping.

## Testing

Mappings should be tested using representative source events.

A mapping test should contain at minimum:

```text
testdata/
└── windows/
    └── sysmon/
        └── <event>/
            ├── input.json
            └── expected.ocsf.json
```

Tests should verify:

- successful parsing;
- correct field normalization;
- correct OCSF class selection;
- correct attribute mapping;
- required OCSF attributes;
- schema validity;
- handling of malformed input;
- handling of missing optional fields;
- handling of unmapped source attributes.

## Contributing

Contributions are welcome.

Changes should be developed in a separate branch and submitted through a Pull Request.

Recommended branch naming:

```text
feature/<feature-name>
fix/<issue-name>
refactor/<area>
test/<area>
docs/<topic>
```

For example:

```text
feature/sysmon-to-ocsf
feature/zeek-to-ocsf
fix/sysmon-process-mapping
test/sysmon-parser
docs/mapping-guide
```

When adding a new mapping, contributors should provide representative source events and expected OCSF output whenever possible.

Do not commit credentials, API keys, personally identifiable information, or sensitive production telemetry as test data.

## References

- [Open Cybersecurity Schema Framework](https://github.com/ocsf)
- [OCSF Schema](https://github.com/ocsf/ocsf-schema)
- [OCSF Documentation](https://github.com/ocsf/ocsf-docs)
- [OCSF Examples](https://github.com/ocsf/examples)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)

## License

This project is licensed under the **BSD 2-Clause License**.

See [LICENSE](LICENSE) for details.

---

**OCSF Mapper** is part of the **AgenticSOC** project.
