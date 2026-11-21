"""Tiny dependency-free PDF table writer (landscape A4, built-in Helvetica)."""

PAGE_W, PAGE_H = 842, 595
MARGIN = 28
LINE_H = 12
FONT_SIZE = 7.5


def _esc(text):
    text = str(text if text is not None else "")
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _clip(text, width_chars):
    text = str(text if text is not None else "").replace("\n", " ")
    return text if len(text) <= width_chars else text[: max(width_chars - 1, 1)] + "~"


def make_pdf(title, subtitle, columns, rows):
    """columns: list of (header, width_in_points). rows: list of lists of str."""
    usable_h = PAGE_H - 2 * MARGIN - 40
    rows_per_page = max(int(usable_h // LINE_H) - 1, 1)
    pages = [rows[i:i + rows_per_page] for i in range(0, len(rows), rows_per_page)] or [[]]

    objects = []  # each is bytes of the object body

    def add(body):
        objects.append(body if isinstance(body, bytes) else body.encode("latin-1"))
        return len(objects)

    catalog_id = add("")      # 1 placeholder
    pages_id = add("")        # 2 placeholder
    font_id = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold_id = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_ids = []
    total = len(pages)
    for n, page_rows in enumerate(pages, 1):
        y = PAGE_H - MARGIN
        parts = [f"BT /F2 12 Tf {MARGIN} {y} Td ({_esc(title)}) Tj ET"]
        y -= 14
        parts.append(f"BT /F1 8 Tf {MARGIN} {y} Td ({_esc(subtitle)}  -  page {n} of {total}) Tj ET")
        y -= 22
        x = MARGIN
        for header, width in columns:
            parts.append(f"BT /F2 {FONT_SIZE} Tf {x} {y} Td ({_esc(header)}) Tj ET")
            x += width
        y -= 3
        parts.append(f"{MARGIN} {y} m {PAGE_W - MARGIN} {y} l S")
        y -= LINE_H - 2
        for row in page_rows:
            x = MARGIN
            for (header, width), cell in zip(columns, row):
                chars = int(width / (FONT_SIZE * 0.52))
                parts.append(
                    f"BT /F1 {FONT_SIZE} Tf {x} {y} Td ({_esc(_clip(cell, chars))}) Tj ET"
                )
                x += width
            y -= LINE_H
        stream = "\n".join(parts).encode("latin-1")
        content_id = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page_id = add(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 {font_id} 0 R /F2 {bold_id} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        )
        page_ids.append(page_id)

    kids = " ".join(f"{p} 0 R" for p in page_ids)
    objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1")
    objects[pages_id - 1] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")
    )

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, catalog_id, xref,
    )
    return bytes(out)
