# Logs

This directory stores raw and annotated log files from malware analysis or incident response.

## Naming Convention

`YYYY-MM-DD_<source>_<brief-description>.<ext>`

Examples:
- `2024-03-15_wireshark_emotet-c2-traffic.pcapng`
- `2024-03-15_procmon_ransomware-execution.csv`
- `2024-03-15_sysmon_lateral-movement.evtx`

## Notes

- Do **not** commit live malware samples or passwords in this directory.
- Annotate logs where possible to aid future analysis.
