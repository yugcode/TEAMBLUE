import re


RULES = [
    {
        "id": "R001",
        "mitre_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "severity": 6.0,
        "match": lambda e: (
            e["event_data"].get("action_taken") in ("ssh_auth_attempt", "login_attempt")
            and e["event_data"].get("status") == "failed"
        )
    },
    {
        "id": "R002",
        "mitre_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "severity": 8.0,
        "match": lambda e: _raw_contains(e, r"powershell|pwsh|-enc|-encodedcommand")
    },
    {
        "id": "R003",
        "mitre_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "severity": 7.0,
        "match": lambda e: _raw_contains(e, r"schtasks|at\.exe|task scheduler")
    },
    {
        "id": "R004",
        "mitre_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "severity": 9.5,
        "match": lambda e: _raw_contains(e, r"lsass|mimikatz|sekurlsa|procdump")
    },
    {
        "id": "R005",
        "mitre_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "severity": 5.0,
        "match": lambda e: _raw_contains(e, r"dns query|nslookup|dig ") and _raw_contains(e, r"suspicious|unusual|blocked")
    },
    {
        "id": "R006",
        "mitre_id": "T1570",
        "technique_name": "Lateral Tool Transfer",
        "severity": 8.5,
        "match": lambda e: _raw_contains(e, r"psexec|wmic.*process|smbclient")
    },
    {
        "id": "R007",
        "mitre_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "severity": 6.5,
        "match": lambda e: _raw_contains(e, r"rdp|3389|mstsc")
    },
    {
        "id": "R008",
        "mitre_id": "T1055",
        "technique_name": "Process Injection",
        "severity": 9.0,
        "match": lambda e: _raw_contains(e, r"virtualalloc|writeprocessmemory|createremotethread")
    },
    {
        "id": "R009",
        "mitre_id": "T1078",
        "technique_name": "Valid Accounts",
        "severity": 7.5,
        "match": lambda e: (
            e["event_data"].get("action_taken") in ("ssh_auth_attempt", "login_attempt")
            and e["event_data"].get("status") == "success"
            and _raw_contains(e, r"root|admin|administrator")
        )
    },
    {
        "id": "R010",
        "mitre_id": "T1548.003",
        "technique_name": "Abuse Elevation Control: Sudo",
        "severity": 7.0,
        "match": lambda e: e["event_data"].get("action_taken") == "sudo_execution"
    },
]


def _raw_contains(event, pattern):
    raw = event["event_data"].get("raw_log", "") or ""
    return bool(re.search(pattern, raw, re.IGNORECASE))


def map_event(event):
    for rule in RULES:
        try:
            if rule["match"](event):
                event["threat_context"]["mitre_id"] = rule["mitre_id"]
                event["threat_context"]["technique_name"] = rule["technique_name"]
                event["threat_context"]["severity_score"] = rule["severity"]
                event["analysis"]["conclusion"] = "Technique Identified"
                return event
        except Exception:
            continue

    event["analysis"]["conclusion"] = "No Match"
    return event


def map_events(events):
    return [map_event(e) for e in events]
