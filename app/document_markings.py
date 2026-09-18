"""Automatic UNG-VAULT document markings.

Produces presentation metadata for web UI, PDF/rendering pipelines and print.
Authorization remains exclusively in access_policy.authorize().
"""
from html import escape
from app.access_policy import document_marking

def marking_payload(profile_code: str, document_id: str) -> dict:
    m = document_marking(profile_code)
    return {
        **m,
        "document_id": document_id,
        "header": m["banner"],
        "footer": f'{m["profile"]} • {document_id}',
        "print_label": f'[{m["profile"]}] {m["label"]}',
        "accessibility_label": f'Protection profile {m["profile"]}, {m["label"]}, color {m["color_name"]}',
    }

def html_badge(profile_code: str) -> str:
    m = document_marking(profile_code)
    return (
        f'<span class="vault-marking" role="status" '
        f'aria-label="{escape(m["banner"])}" '
        f'style="--vault-mark:{escape(m["color_hex"])}">'
        f'<span class="vault-marking__swatch" aria-hidden="true"></span>'
        f'{escape(m["banner"])}</span>'
    )

def pdf_marking(profile_code: str, document_id: str) -> dict:
    """Renderer-neutral instructions consumed by a PDF generator."""
    p = marking_payload(profile_code, document_id)
    return {
        "top_banner_text": p["header"],
        "top_banner_hex": p["color_hex"],
        "footer_text": p["footer"],
        "repeat_on_every_page": True,
        "monochrome_fallback": p["print_label"],
    }

def print_marking(profile_code: str, document_id: str) -> dict:
    p = marking_payload(profile_code, document_id)
    return {
        "header_text": p["print_label"],
        "footer_text": p["footer"],
        "use_color_when_available": True,
        "color_hex": p["color_hex"],
        "require_text_label": True,
    }
