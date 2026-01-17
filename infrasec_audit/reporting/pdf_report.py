from __future__ import annotations

from pathlib import Path

from infrasec_audit.models import FindingsReport
from infrasec_audit.reporting.html_report import render_html
from infrasec_audit.utils.redact import redact_mapping


def write_pdf(
    report: FindingsReport,
    output_path: Path,
    redact: bool,
    client_name: str | None,
) -> None:
    html = render_html(report, redact=redact, client_name=client_name)
    try:
        from weasyprint import HTML

        HTML(string=html).write_pdf(output_path)
        return
    except Exception:
        pass

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except Exception as exc:  # pragma: no cover - environment-specific
        raise RuntimeError("ReportLab não está disponível para gerar PDF.") from exc

    data = report.model_dump()
    if redact:
        data = redact_mapping(data)

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4)
    story = []
    story.append(Paragraph("InfraSec Audit Report", styles["Title"]))
    story.append(Paragraph(f"Cliente/ambiente: {client_name or '[preencher]'}", styles["Normal"]))
    story.append(Paragraph("Resumo de severidades:", styles["Heading2"]))
    counts = data.get("counts", {})
    for key in ["critical", "high", "medium", "low"]:
        story.append(Paragraph(f"{key.title()}: {counts.get(key, 0)}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Achados:", styles["Heading2"]))
    for finding in data.get("findings", []):
        story.append(
            Paragraph(
                f"{finding.get('cve')} - {finding.get('component')}",
                styles["Heading3"],
            )
        )
        story.append(Paragraph(f"Severidade: {finding.get('severity')}", styles["Normal"]))
        story.append(Paragraph(f"Resumo: {finding.get('summary')}", styles["Normal"]))
        story.append(Spacer(1, 8))
    doc.build(story)
