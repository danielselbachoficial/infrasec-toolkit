from __future__ import annotations

from infrasec_audit.models import EvidenceItem


def parse_osv(data: dict) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for vuln in data.get("results", []) or []:
        for entry in vuln.get("vulnerabilities", []) or []:
            items.append(
                EvidenceItem(
                    source="osv",
                    identifier=entry.get("id", "unknown"),
                    component=(entry.get("package", {}) or {}).get("name"),
                    version=None,
                    severity=(entry.get("severity", [{}])[0] or {}).get("type"),
                    summary=entry.get("summary"),
                    reference=(entry.get("references", [{}])[0] or {}).get("url"),
                )
            )
    return items
