from __future__ import annotations

import xml.etree.ElementTree as ET

from infrasec_audit.models import EvidenceItem


def parse_nmap_xml(raw_xml: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    root = ET.fromstring(raw_xml)
    for host in root.findall("host"):
        address_el = host.find("address")
        address = address_el.get("addr") if address_el is not None else "unknown"
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            service = port.find("service")
            service_name = service.get("name") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            port_id = port.get("portid")
            protocol = port.get("protocol")
            items.append(
                EvidenceItem(
                    source=f"nmap:{address}",
                    identifier=f"{service_name}:{port_id}/{protocol}",
                    component=product or service_name,
                    version=version,
                    summary=f"Open service {service_name} on {address}:{port_id}/{protocol}",
                    reference="",
                )
            )
    return items
