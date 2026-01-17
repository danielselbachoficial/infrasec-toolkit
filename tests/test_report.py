from pathlib import Path

from infrasec_audit.models import FindingsReport, Finding, Recommendation, SystemInfo
from infrasec_audit.reporting.html_report import write_html
from infrasec_audit.reporting.pdf_report import write_pdf


def _sample_report() -> FindingsReport:
    system = SystemInfo(hostname="example", os_name="Linux", os_version="1", kernel="5")
    finding = Finding(
        cve="CVE-2020-0001",
        component="openssl",
        version="1.0",
        severity="high",
        summary="Sample",
        references=["https://example.com"],
        recommendations=[Recommendation(title="Atualizar", details="Aplicar patch")],
    )
    return FindingsReport(
        system=system,
        findings=[finding],
        counts={"high": 1, "critical": 0, "medium": 0, "low": 0},
        risk_score=7,
    )


def test_report_generation(tmp_path: Path):
    report = _sample_report()
    html_path = tmp_path / "index.html"
    pdf_path = tmp_path / "report.pdf"
    write_html(report, html_path, redact=False, client_name="Cliente")
    write_pdf(report, pdf_path, redact=False, client_name="Cliente")
    assert html_path.exists()
    assert pdf_path.exists()
    assert html_path.read_text(encoding="utf-8")
    assert pdf_path.stat().st_size > 0
