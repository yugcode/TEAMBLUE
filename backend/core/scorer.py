def score_event(event):
    base = event["threat_context"].get("severity_score", 0.0)

    if event["event_data"].get("status") == "failed":
        base = min(base + 0.5, 10.0)

    if event["threat_context"].get("cve_id"):
        base = min(base + 1.0, 10.0)

    if base >= 9.0:
        label = "Critical"
    elif base >= 7.0:
        label = "High"
    elif base >= 4.0:
        label = "Medium"
    else:
        label = "Low"

    event["threat_context"]["severity_score"] = round(base, 1)
    event["analysis"]["severity_label"] = label
    return event


def score_events(events):
    return [score_event(e) for e in events]


def coverage_summary(events):
    total = len(events)
    if total == 0:
        return {"total": 0, "matched": 0, "unmatched": 0, "coverage_pct": 0}

    matched = sum(1 for e in events if e["threat_context"]["mitre_id"] is not None)
    unmatched = total - matched
    coverage_pct = round((matched / total) * 100, 1)

    return {
        "total": total,
        "matched": matched,
        "unmatched": unmatched,
        "coverage_pct": coverage_pct
    }
