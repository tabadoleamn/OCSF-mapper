# File System Activity — OCSF 1.9.0 review and corrections

## Installation and scope

Replace aux_ops.py and sysmon.json. The included log_2_ocsf_converter.py is unchanged from the last no-raw_data release; retain your local paths and collector timezone configuration. ops.py is unchanged. All other class mappings remain unchanged.

There is no raw_data output and no explicit unmapped mapping. The existing converter automatically collects unused original source keys into unmapped.

## Findings and corrections

- The file and actor mappings previously called null-returning placeholders. File System Activity requires both objects, along with device. Implemented sysmon_target_file and a dedicated sysmon_file_actor, leaving unrelated generic actor placeholders deferred.
- device.type_id=5 incorrectly classified every host as Mobile. The existing host helper now provides hostname/Computer fallback and host_ip, with type_id=0 / Unknown when no host-type evidence exists.
- Source severities now normalize case-insensitively. INFO -> Informational, warnings -> Medium, errors -> High, critical -> Critical, and so on. Windows Level accepts numeric strings or integers; collector SeverityValue is not assumed to be a Windows level. Unrecognized source severity keeps its text with ID 99. Missing severity on a recognized native file event falls back to Informational.
- Status ID/name pairs are consistent. Explicit statuses are normalized; unknown source strings use 99 with original text. Native observed creation/change/deletion events infer Success when no explicit Status is provided. Events 27/28 always report Failure of the requested file operation, not failure of Sysmon's blocking action. A contradictory raw Status is left unused and therefore preserved by automatic unmapped handling for blocked events.
- Activity/type IDs and names are computed together in the custom stage, avoiding an expr dependency on activity_id that the standard stage cannot see.

## Activity decisions

| Sysmon ID | Source meaning | OCSF activity | Native default status |
|---|---|---|---|
| 2 | Creation timestamp changed | 6 / Set Attributes | Success |
| 11 | File created OR overwritten | 99 / FileCreate | Success |
| 15 | Named stream created | 1 / Create | Success |
| 23 | File deleted and archived | 4 / Delete | Success |
| 26 | File deletion detected | 4 / Delete | Success |
| 27 | Executable creation blocked | 1 / Create (attempt) | Failure |
| 28 | File shredding blocked | 99 / FileBlockShredding | Failure |
| 29 | New executable detected | 1 / Create | Success |
| Missing EventID (helper behavior) | Unknown | 0 / Unknown | Unknown |
| Unexpected EventID (helper behavior) | Unsupported | 99 / Category or Sysmon Event N | Unknown |

Event 11's Other mapping is deliberately conservative: Microsoft documents both creation and overwriting, but the event ID does not distinguish them. OCSF has separate Create and Update activities. Event 28 likewise does not establish a Delete operation; shredding can overwrite data. No unsupported activity is guessed.

## Added mappings

The block has 37 mapping targets; object-producing operations supply multiple nested fields.

- Metadata: schema/product identity, source UID, original RecordNumber, EventID, log version, original UTC time, log level, channel/provider, collector logged_time when timezone is known, host/security_control profiles.
- Classification: activity_id/name, type_uid/name, severity_id/name, status_id/name.
- Host: device identity and Unknown device type, without guessing workstation/server/mobile.
- Actor: native ProcessId (case-sensitive), ProcessGuid, Image-derived process path/name/file, User split into domain/name, and CommandLine when supplied. Provider ProcessID is not the file-operation process PID and stays unmapped.
- File: TargetFilename-derived name/path/parent folder/extension; Regular File versus Executable File inferred from IsExecutable or Event IDs 27/29; supplied file size; supplied hashes; UTC creation time; deleted flag on successful events 23/26.
- Event 2: file.created_time receives PreviousCreationUtcTime; file_result.created_time receives CreationUtcTime on success. Both objects retain the same target identity. The previous creation timestamp is not incorrectly mapped as last-modified time.
- Event 15: preserve the named-stream path. Do not infer an extension or executable type from the base file, and do not assign the unnamed/base file's Hash/Hashes to the named stream. Those hashes remain unmapped automatically.
- Security-control profile: events 27/28 -> action Denied / disposition Blocked; other supported IDs -> Observed / Logged. A blocked event is not arbitrarily escalated to a higher severity.
- Message is mapped when present.

## Constants retained intentionally

OCSF schema version, Sysmon/Microsoft product identity, category_uid=1, class_uid=1001, their captions, and declared profiles describe this mapping and should remain constant. timezone_offset=0 matches the UTC source timestamp. Unknown device type is the correct fallback in the absence of device classification data.

## Source limits and unmapped behavior

- Missing TargetFilename can prevent creation of required file; missing process/user identity can prevent actor; missing host identity can prevent device. The code does not fabricate required source data. Such incomplete source events are not guaranteed to pass strict validation.
- Archived, RuleName, provider/account/thread context, stream Contents, and other unused fields remain under automatic unmapped. Archived does not by itself provide the archive-copy path or justify a quarantine disposition. RuleName is a Sysmon filter label, not automatically a firewall rule.
- Existing source-use accounting treats reading an input as use, even when a transformation rejects it. This behavior is unchanged.
- Collector timestamps still require configured timezone information; the converter's previous setting is unchanged.

## Verification

Passed Python/JSON syntax; all eight routed file IDs; OCSF 1.9.0 required nested fields, object constraints, types, enums and standard sibling labels; type ID calculation and custom Other names; severity and explicit status cases; security-control actions; Event 2 before/after timestamps; Event 15 hash separation; provider PID separation; automatic unmapped; UTC/Asia-Tehran timezone independence; and unchanged converter/other classes. Tests execute the supplied basic operation dispatcher and actual custom/converter functions. Full installed apply_stream execution was not tested. Fixtures containing the required source data pass these targeted schema checks.

## Sources

- https://schema.ocsf.io/api/1.9.0/classes/file_activity
- https://schema.ocsf.io/api/1.9.0/objects/file
- https://schema.ocsf.io/api/1.9.0/objects/fingerprint
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## Updated function locations

- `sysmon_target_file`: lines 1784–1785
- `sysmon_file_activity_id`: lines 1798–1802
- `sysmon_file_activity_name`: lines 1805–1811
- `sysmon_file_type_uid`: lines 1814–1815
- `sysmon_file_type_name`: lines 1818–1819
- `_sysmon_file_severity_pair`: lines 1822–1838
- `sysmon_file_severity_id`: lines 1841–1842
- `sysmon_file_severity`: lines 1845–1846
- `sysmon_file_status_id`: lines 1849–1856
- `sysmon_file_status`: lines 1859–1863
- `sysmon_file_actor`: lines 1866–1878
- `_sysmon_target_file`: lines 1881–1917
- `sysmon_file_result`: lines 1920–1927

Exact edits are in project_changes.diff.
