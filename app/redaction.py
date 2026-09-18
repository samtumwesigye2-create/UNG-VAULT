from __future__ import annotations

import hashlib
import io
import random
from dataclasses import dataclass

import fitz  # PyMuPDF
from PIL import Image, ImageDraw


@dataclass(frozen=True)
class RedactionResult:
    data: bytes
    media_type: str
    suffix: str


def _validate_percentage(value: int) -> int:
    if value < 0 or value > 95:
        raise ValueError("redaction percentage must be between 0 and 95")
    return value


def _seed(data: bytes, percentage: int, page_index: int = 0) -> int:
    digest = hashlib.sha256(data + percentage.to_bytes(2, "big") + page_index.to_bytes(4, "big")).digest()
    return int.from_bytes(digest[:8], "big")


def _rectangles(width: float, height: float, percentage: int, seed: int):
    """Generate non-overlapping black blocks covering approximately percentage of page area.

    The layout is deterministic for the same input and percentage, which makes exports
    reproducible and auditable.
    """
    if percentage <= 0:
        return []

    rng = random.Random(seed)
    target = width * height * (percentage / 100.0)
    covered = 0.0
    rects = []

    # Use a grid so blocks do not overlap and the requested coverage remains predictable.
    cols, rows = 8, 12
    cell_w, cell_h = width / cols, height / rows
    cells = [(c, r) for r in range(rows) for c in range(cols)]
    rng.shuffle(cells)

    for c, r in cells:
        if covered >= target:
            break

        # Most blocks span 1-3 cells horizontally and 1-2 vertically.
        span_c = rng.choice((1, 1, 2, 2, 3))
        span_r = rng.choice((1, 1, 1, 2))
        x0 = c * cell_w
        y0 = r * cell_h
        x1 = min(width, (c + span_c) * cell_w)
        y1 = min(height, (r + span_r) * cell_h)

        candidate_area = (x1 - x0) * (y1 - y0)
        remaining = target - covered
        if candidate_area > remaining and remaining > cell_w * cell_h * 0.35:
            # Trim the last block to avoid overshooting too far.
            y1 = y0 + max(1.0, remaining / max(1.0, (x1 - x0)))
            y1 = min(height, y1)
            candidate_area = (x1 - x0) * (y1 - y0)

        rects.append((x0, y0, x1, y1))
        covered += candidate_area

    return rects


def redact_image(data: bytes, percentage: int, media_type: str) -> RedactionResult:
    percentage = _validate_percentage(percentage)
    with Image.open(io.BytesIO(data)) as src:
        img = src.convert("RGB")
        draw = ImageDraw.Draw(img)
        for rect in _rectangles(img.width, img.height, percentage, _seed(data, percentage)):
            draw.rectangle(rect, fill=(0, 0, 0))

        out = io.BytesIO()
        if media_type == "image/png":
            img.save(out, format="PNG", optimize=True)
            return RedactionResult(out.getvalue(), "image/png", ".redacted.png")
        img.save(out, format="JPEG", quality=94, optimize=True)
        return RedactionResult(out.getvalue(), "image/jpeg", ".redacted.jpg")


def redact_pdf(data: bytes, percentage: int) -> RedactionResult:
    percentage = _validate_percentage(percentage)
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        for idx, page in enumerate(doc):
            rect = page.rect
            for x0, y0, x1, y1 in _rectangles(
                rect.width, rect.height, percentage, _seed(data, percentage, idx)
            ):
                page.add_redact_annot(
                    fitz.Rect(rect.x0 + x0, rect.y0 + y0, rect.x0 + x1, rect.y0 + y1),
                    fill=(0, 0, 0),
                )
            if percentage:
                # This removes underlying text/images rather than merely drawing over them.
                page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS)
        out = doc.tobytes(garbage=4, deflate=True, clean=True)
        return RedactionResult(out, "application/pdf", ".redacted.pdf")
    finally:
        doc.close()


def redact_file(data: bytes, percentage: int, media_type: str, filename: str) -> RedactionResult:
    mt = (media_type or "").lower()
    name = (filename or "").lower()
    if mt == "application/pdf" or name.endswith(".pdf"):
        return redact_pdf(data, percentage)
    if mt in {"image/png", "image/jpeg"} or name.endswith((".png", ".jpg", ".jpeg")):
        normalized = "image/png" if name.endswith(".png") or mt == "image/png" else "image/jpeg"
        return redact_image(data, percentage, normalized)
    raise ValueError("Selective redaction currently supports PDF, PNG and JPEG files")
