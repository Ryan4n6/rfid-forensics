"""Generate PDF forensic reports using reportlab (optional dependency)."""

import datetime
from pathlib import Path
from typing import Optional

from .dump_loader import MfcCard
from .key_fingerprint import KeyAnalysis
from .report import ChainOfCustody, _generate_forensic_notes, _generate_leads
from .structure_detect import StructureAnalysis


def check_reportlab():
    try:
        import reportlab
        return True
    except ImportError:
        return False


def generate_pdf(
    card: MfcCard,
    key_analysis: KeyAnalysis,
    structure: StructureAnalysis,
    output_path: str,
    custody: Optional[ChainOfCustody] = None,
):
    """Generate a formatted PDF forensic report."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        NextPageTemplate,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    PAGE_W, PAGE_H = letter
    MARGIN = 0.75 * inch

    styles = getSampleStyleSheet()

    s_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=16,
        leading=20,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
    )
    s_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=12,
    )
    s_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=14,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
        borderWidth=0,
        borderPadding=0,
    )
    s_body = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        spaceAfter=4,
    )
    s_mono = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontSize=7.5,
        leading=10,
        fontName="Courier",
        spaceAfter=2,
    )
    s_note = ParagraphStyle(
        "Note",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        leftIndent=12,
        spaceAfter=4,
        textColor=colors.HexColor("#333333"),
    )
    s_disclaimer = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )

    TABLE_STYLE = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ])

    HEX_TABLE_STYLE = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d2d2d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#999999")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f8f8"), colors.white]),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ])

    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    case_label = custody.case_number if custody and custody.case_number else "N/A"

    def header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(MARGIN, PAGE_H - 0.5 * inch, "RFID FORENSICS")
        canvas.drawRightString(
            PAGE_W - MARGIN, PAGE_H - 0.5 * inch, f"Case: {case_label}"
        )
        canvas.setStrokeColor(colors.HexColor("#cccccc"))
        canvas.line(MARGIN, PAGE_H - 0.55 * inch, PAGE_W - MARGIN, PAGE_H - 0.55 * inch)
        canvas.line(MARGIN, 0.6 * inch, PAGE_W - MARGIN, 0.6 * inch)
        canvas.drawString(
            MARGIN, 0.45 * inch, f"Generated: {timestamp}"
        )
        canvas.drawRightString(
            PAGE_W - MARGIN, 0.45 * inch, f"Page {doc.page}"
        )
        canvas.restoreState()

    frame = Frame(
        MARGIN, 0.75 * inch,
        PAGE_W - 2 * MARGIN, PAGE_H - 1.5 * inch,
        id="main",
    )
    template = PageTemplate(id="main", frames=[frame], onPage=header_footer)
    doc = BaseDocTemplate(
        output_path,
        pagesize=letter,
        pageTemplates=[template],
        title=f"RFID Forensic Report - {card.uid}",
        author=custody.examiner_name if custody else "rfid-forensics",
    )

    elements = []

    # Title block
    elements.append(Paragraph("CONTACTLESS CARD ANALYSIS REPORT", s_title))
    elements.append(Paragraph(
        f"rfid-forensics v0.1.0 &bull; {timestamp} &bull; Card UID: {card.uid}",
        s_subtitle,
    ))
    elements.append(Spacer(1, 8))

    # Chain of custody
    if custody:
        elements.append(Paragraph("CHAIN OF CUSTODY", s_heading))
        coc_data = []
        if custody.examiner_name:
            coc_data.append(["Examiner", custody.examiner_name])
        if custody.examiner_badge:
            coc_data.append(["Badge/ID", custody.examiner_badge])
        if custody.agency:
            coc_data.append(["Agency", custody.agency])
        if custody.case_number:
            coc_data.append(["Case Number", custody.case_number])
        if custody.evidence_number:
            coc_data.append(["Evidence Number", custody.evidence_number])
        if custody.date_acquired:
            coc_data.append(["Date Acquired", custody.date_acquired])
        coc_data.append(["Acquisition Tool", custody.acquisition_tool])
        coc_data.append(["Method", custody.acquisition_method])
        coc_data.append(["Write Blocked", "Yes" if custody.write_blocked else "No (see notes)"])
        if custody.notes:
            coc_data.append(["Notes", custody.notes])

        coc_table = Table(coc_data, colWidths=[1.8 * inch, 4.5 * inch])
        coc_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(coc_table)
        elements.append(Spacer(1, 8))

    # Source file
    elements.append(Paragraph("SOURCE FILE INTEGRITY", s_heading))
    src_data = [
        ["File", card.source_file],
        ["SHA-256", card.source_hash],
    ]
    src_table = Table(src_data, colWidths=[1.2 * inch, 5.1 * inch])
    src_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(src_table)
    elements.append(Spacer(1, 6))

    # Card identification
    elements.append(Paragraph("CARD IDENTIFICATION", s_heading))
    card_data = [
        ["Type", card.card_type],
        ["UID", card.uid],
        ["ATQA", card.atqa],
        ["SAK", card.sak],
        ["Sectors with data", ", ".join(str(s) for s in structure.data_sectors)],
        ["Empty sectors", f"{len(structure.empty_sectors)} of {card.num_sectors}"],
    ]
    if structure.card_type_byte:
        card_data.append(["Card type byte", structure.card_type_byte])

    card_table = Table(card_data, colWidths=[1.8 * inch, 4.5 * inch])
    card_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(card_table)
    elements.append(Spacer(1, 6))

    # Vendor fingerprint
    elements.append(Paragraph("VENDOR FINGERPRINT", s_heading))
    vf_lines = []
    if key_analysis.vendor_guess:
        vf_lines.append(f"<b>Probable vendor:</b> {key_analysis.vendor_guess}")
    else:
        vf_lines.append("<b>Probable vendor:</b> Unattributed")
    if key_analysis.system_guess:
        vf_lines.append(f"<b>Probable system:</b> {key_analysis.system_guess}")
    vf_lines.append(f"<b>Unique keys:</b> {len(key_analysis.unique_keys)}")
    vf_lines.append(
        f"<b>Key diversity:</b> {key_analysis.key_diversity_score:.2f} (0=uniform, 1=all unique)"
    )
    ds = key_analysis.default_key_sectors
    vf_lines.append(f"<b>Default-key sectors:</b> {ds if ds else 'None'}")
    for line in vf_lines:
        elements.append(Paragraph(line, s_body))

    if key_analysis.matches:
        elements.append(Spacer(1, 4))
        s_cell = ParagraphStyle("CellText", fontSize=7, leading=9, fontName="Helvetica")
        s_cell_mono = ParagraphStyle("CellMono", fontSize=7, leading=9, fontName="Courier")
        s_cell_hdr = ParagraphStyle(
            "CellHdr", fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=colors.white,
        )

        key_rows = [[
            Paragraph("Key", s_cell_hdr),
            Paragraph("Vendor / System", s_cell_hdr),
            Paragraph("Conf.", s_cell_hdr),
            Paragraph("Sectors", s_cell_hdr),
        ]]
        for m in key_analysis.matches:
            sectors = key_analysis.unique_keys.get(m.key_hex, [])
            sector_str = ", ".join(s.replace("Sector ", "S").replace(" Key ", " K") for s in sectors)
            key_rows.append([
                Paragraph(m.key_hex, s_cell_mono),
                Paragraph(f"{m.vendor}<br/><i>{m.system}</i>", s_cell),
                Paragraph(m.confidence, s_cell),
                Paragraph(sector_str, s_cell),
            ])

        avail_w = PAGE_W - 2 * MARGIN
        key_table = Table(
            key_rows,
            colWidths=[1.05 * inch, 1.7 * inch, 0.6 * inch, avail_w - 3.35 * inch],
        )
        key_table.setStyle(TABLE_STYLE)
        elements.append(key_table)

    if key_analysis.unmatched:
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<b>Unmatched keys:</b>", s_body))
        for k in key_analysis.unmatched:
            sectors = key_analysis.unique_keys.get(k, [])
            elements.append(Paragraph(
                f"<font face='Courier' size='7'>{k}</font>: {', '.join(sectors)}",
                s_note,
            ))

    elements.append(Spacer(1, 6))

    # Hex dump
    elements.append(Paragraph("DATA SECTORS (NON-EMPTY BLOCKS)", s_heading))
    hex_rows = [["Sector", "Block", "Hex Data", "ASCII"]]
    for sector in structure.data_sectors:
        for blk in card.sector_data_blocks(sector):
            data = card.blocks.get(blk, b'\x00' * 16)
            if data != b'\x00' * 16:
                hex_str = " ".join(f"{b:02X}" for b in data)
                ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)
                hex_rows.append([str(sector), str(blk), hex_str, ascii_str])

    if len(hex_rows) > 1:
        avail_w = PAGE_W - 2 * MARGIN
        hex_table = Table(
            hex_rows,
            colWidths=[0.5 * inch, 0.5 * inch, avail_w - 2.3 * inch, 1.3 * inch],
        )
        hex_table.setStyle(HEX_TABLE_STYLE)
        elements.append(hex_table)
    else:
        elements.append(Paragraph("No non-empty data blocks found.", s_body))

    elements.append(Spacer(1, 6))

    # Audit log
    if structure.has_audit_log:
        elements.append(Paragraph("AUDIT LOG", s_heading))

        lock_ids = set(r.lock_id for r in structure.audit_records)
        dup_count = len(structure.audit_records) - structure.distinct_audit_count
        dup_text = (
            f" ({structure.distinct_audit_count} distinct, {dup_count} exact duplicate"
            f"{'s' if dup_count > 1 else ''})" if dup_count else ""
        )
        elements.append(Paragraph(
            f"<b>{len(structure.audit_records)} records</b>{dup_text} found in sector {structure.audit_sector}. "
            f"Lock ID(s): {', '.join(f'0x{lid:04X}' for lid in sorted(lock_ids))}",
            s_body,
        ))
        elements.append(Spacer(1, 4))

        audit_rows = [["#", "Time", "Event", "Description", "Lock", "Checksum"]]
        for i, r in enumerate(structure.audit_records):
            time_str = r.timestamp_guess or f"cnt={r.counter}"
            label = r.event_label or f"Unknown (0x{r.event_type:02X})"
            if r.duplicate_of is not None:
                label += f" [DUP of #{r.duplicate_of}]"
            chk = "OK" if r.checksum_valid else "BAD"
            audit_rows.append([
                str(i),
                time_str,
                f"0x{r.event_type:02X}",
                label,
                f"0x{r.lock_id:04X}",
                chk,
            ])

        avail_w = PAGE_W - 2 * MARGIN
        audit_table = Table(
            audit_rows,
            colWidths=[0.3 * inch, 0.9 * inch, 0.6 * inch, avail_w - 3.5 * inch, 0.7 * inch, 0.7 * inch],
            repeatRows=1,
        )

        audit_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ])
        audit_table.setStyle(audit_style)
        elements.append(audit_table)

        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "<i>NOTE: Timestamps are heuristic. 'Seconds from midnight' is the most "
            "common encoding for hotel locks, but the base date must be corroborated "
            "with external evidence (folio, PMS logs, or lock audit download).</i>",
            s_note,
        ))

        # Raw audit hex
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("Raw Audit Records", s_heading))
        raw_rows = [["#", "Location", "Raw Hex", "Checksum"]]
        for i, r in enumerate(structure.audit_records):
            hex_str = " ".join(f"{b:02X}" for b in r.raw)
            raw_rows.append([
                str(i),
                f"Blk {r.block}+{r.offset}",
                hex_str,
                ("valid" if r.checksum_valid else "INVALID")
                + (f" (dup #{r.duplicate_of})" if r.duplicate_of is not None else ""),
            ])

        avail_w = PAGE_W - 2 * MARGIN
        raw_table = Table(
            raw_rows,
            colWidths=[0.3 * inch, 0.9 * inch, avail_w - 2.4 * inch, 1.2 * inch],
        )
        raw_table.setStyle(HEX_TABLE_STYLE)
        elements.append(raw_table)
        elements.append(Spacer(1, 6))

    # Forensic notes
    elements.append(Paragraph("FORENSIC NOTES", s_heading))
    notes = _generate_forensic_notes(card, key_analysis, structure)
    for note in notes:
        safe_note = note.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(f"&bull; {safe_note}", s_note))
    elements.append(Spacer(1, 6))

    # Investigative leads
    elements.append(Paragraph("INVESTIGATIVE LEADS", s_heading))
    leads = _generate_leads(card, key_analysis, structure)
    for lead in leads:
        safe_lead = lead.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(f"&bull; {safe_lead}", s_note))
    elements.append(Spacer(1, 12))

    # Footer disclaimer
    elements.append(Paragraph(
        "This report was generated by rfid-forensics v0.1.0, an open-source forensic analysis tool. "
        "All findings are based on heuristic analysis of card data and should be corroborated "
        "with independent evidence before use in legal proceedings.",
        s_disclaimer,
    ))

    doc.build(elements)
    return output_path
