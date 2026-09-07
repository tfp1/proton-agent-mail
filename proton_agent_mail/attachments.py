"""Pull attachments out of a raw RFC822 message. Stdlib only.

We parse MIME here rather than shelling out to `himalaya attachment download`
because that command writes one file per attachment using the *sender's*
filename. Those names are attacker-controlled, so letting them reach the
filesystem invites traversal and collision handling we would rather not own.
Exporting the raw message and walking it in memory keeps that off disk.
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any

_FILENAME_OK = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(name: str | None, index: int) -> str:
    """A filename safe to put in a Content-Disposition header.

    The sender chooses this string. Unfiltered it could carry CR/LF and inject
    response headers, or path separators and escape a download directory.
    """
    if not name:
        return f"attachment-{index}"
    cleaned = _FILENAME_OK.sub("_", name)[:120].strip("._-")
    return cleaned or f"attachment-{index}"


def _is_attachment(part: EmailMessage) -> bool:
    if part.is_multipart():
        return False
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    # inline parts that carry a filename count too -- documents attached by
    # Outlook and by most broker/insurer systems arrive as inline, not attachment
    return disp == "inline" and part.get_filename() is not None


def _parts(raw: bytes) -> list[EmailMessage]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return [p for p in msg.walk() if _is_attachment(p)]


def listing(raw: bytes) -> list[dict[str, Any]]:
    """Metadata for every attachment, in message order. Index is the handle."""
    out = []
    for i, p in enumerate(_parts(raw)):
        body = p.get_payload(decode=True) or b""
        out.append(
            {
                "index": i,
                "filename": p.get_filename(),
                "safe_filename": safe_filename(p.get_filename(), i),
                "content_type": p.get_content_type(),
                "size": len(body),
            }
        )
    return out


def payload(raw: bytes, index: int) -> tuple[bytes, str, str]:
    """(bytes, content_type, safe filename) for one attachment."""
    parts = _parts(raw)
    if index < 0 or index >= len(parts):
        raise IndexError("no such attachment")
    p = parts[index]
    return (
        p.get_payload(decode=True) or b"",
        p.get_content_type(),
        safe_filename(p.get_filename(), index),
    )
