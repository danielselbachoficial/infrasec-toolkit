import json
from pathlib import Path

from infrasec_audit.parsers import parse_grype, parse_nmap_xml, parse_osv, parse_trivy


def test_parse_trivy():
    data = json.loads(Path("examples/trivy.json").read_text(encoding="utf-8"))
    items = parse_trivy(data)
    assert items
    assert items[0].identifier == "CVE-2023-1234"


def test_parse_grype():
    data = json.loads(Path("examples/grype.json").read_text(encoding="utf-8"))
    items = parse_grype(data)
    assert items
    assert items[0].component == "nginx"


def test_parse_osv():
    data = json.loads(Path("examples/osv.json").read_text(encoding="utf-8"))
    items = parse_osv(data)
    assert items
    assert items[0].identifier == "CVE-2021-0001"


def test_parse_nmap():
    raw = Path("examples/nmap.xml").read_text(encoding="utf-8")
    items = parse_nmap_xml(raw)
    assert items
    assert items[0].component == "OpenSSH"
