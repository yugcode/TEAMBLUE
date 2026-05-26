import json
import csv
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_event(source_name, raw_line=""):
    return {
        "event_meta": {
            "uuid": str(uuid.uuid4()),
            "ingest_timestamp": _now(),
            "original_source": source_name
        },
        "event_data": {
            "source_ip": None,
            "destination_ip": None,
            "action_taken": None,
            "status": None,
            "raw_log": raw_line
        },
        "threat_context": {
            "mitre_id": None,
            "technique_name": None,
            "severity_score": 0.0,
            "cve_id": None
        },
        "analysis": {
            "conclusion": "Pending",
            "analyst_notes": "",
            "severity_label": "Unknown"
        }
    }


def _parse_syslog_line(line):
    event = _base_event("syslog", line.strip())
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    if len(ip_matches) >= 1:
        event["event_data"]["source_ip"] = ip_matches[0]
    if len(ip_matches) >= 2:
        event["event_data"]["destination_ip"] = ip_matches[1]

    line_lower = line.lower()
    if "failed" in line_lower or "failure" in line_lower:
        event["event_data"]["status"] = "failed"
    elif "accepted" in line_lower or "success" in line_lower:
        event["event_data"]["status"] = "success"

    if "ssh" in line_lower or "sshd" in line_lower:
        event["event_data"]["action_taken"] = "ssh_auth_attempt"
    elif "sudo" in line_lower:
        event["event_data"]["action_taken"] = "sudo_execution"
    elif "login" in line_lower:
        event["event_data"]["action_taken"] = "login_attempt"

    return event


def _parse_json_line(line, source_name):
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    event = _base_event(source_name, line.strip())
    ed = event["event_data"]
    ed["source_ip"] = raw.get("src_ip") or raw.get("source_ip") or raw.get("srcip")
    ed["destination_ip"] = raw.get("dst_ip") or raw.get("destination_ip") or raw.get("dstip")
    ed["action_taken"] = raw.get("action") or raw.get("action_taken") or raw.get("event_type")
    ed["status"] = raw.get("status") or raw.get("outcome")
    return event


def _parse_csv_content(content):
    events = []
    reader = csv.DictReader(content.splitlines())
    for row in reader:
        event = _base_event("csv", str(row))
        ed = event["event_data"]
        ed["source_ip"] = row.get("src_ip") or row.get("source_ip")
        ed["destination_ip"] = row.get("dst_ip") or row.get("destination_ip")
        ed["action_taken"] = row.get("action") or row.get("action_taken")
        ed["status"] = row.get("status") or row.get("outcome")
        events.append(event)
    return events


def ingest_stream(file_stream, filename):
    suffix = Path(filename).suffix.lower()
    content = file_stream.read().decode("utf-8")
    events = []

    if suffix == ".csv":
        events = _parse_csv_content(content)

    elif suffix == ".json":
        content = content.strip()
        if content.startswith("["):
            raw_list = json.loads(content)
            for item in raw_list:
                event = _base_event(filename, json.dumps(item))
                ed = event["event_data"]
                ed["source_ip"] = item.get("src_ip") or item.get("source_ip")
                ed["destination_ip"] = item.get("dst_ip") or item.get("destination_ip")
                ed["action_taken"] = item.get("action") or item.get("action_taken")
                ed["status"] = item.get("status") or item.get("outcome")
                events.append(event)
        else:
            for line in content.splitlines():
                line = line.strip()
                if line:
                    event = _parse_json_line(line, filename)
                    if event:
                        events.append(event)

    elif suffix in (".log", ".txt", ""):
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            event = _parse_json_line(line, filename)
            if event:
                events.append(event)
            else:
                events.append(_parse_syslog_line(line))

    return events
