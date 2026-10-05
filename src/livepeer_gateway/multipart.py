"""``multipart/form-data`` request bodies for ``call_runner``.

OpenAI-style audio endpoints (``/v1/audio/transcriptions``, ``/v1/audio/translations``)
take a multipart upload: a ``file`` part plus plain fields such as ``model``. A
``MultipartBody`` describes such a request. Content is held in memory as bytes,
never as a stream, so the exact same body can be sent again after a 402 payment
challenge. Keep that in mind for large uploads: an audio clip of a few megabytes
is fine, and the SDK already buffers responses of that size.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

__all__ = ["FilePart", "MultipartBody", "encode_multipart"]


@dataclass(frozen=True)
class FilePart:
    """One file part of a multipart body."""

    name: str
    """Form field name, e.g. ``"file"``."""
    filename: str
    """File name reported to the server, e.g. ``"audio.wav"``."""
    content: bytes
    """The file bytes, held in memory so the request can be re-sent."""
    content_type: str = "application/octet-stream"


@dataclass(frozen=True)
class MultipartBody:
    """A ``multipart/form-data`` body: plain fields plus file parts.

    The boundary is fixed when the body is created, so encoding the same
    ``MultipartBody`` twice (as the payment retry does) yields identical bytes.
    """

    fields: Mapping[str, str] = field(default_factory=dict)
    """Plain form fields, e.g. ``{"model": "whisper-large-v3"}``."""
    files: Sequence[FilePart] = ()
    boundary: str = ""

    def __post_init__(self) -> None:
        if not self.boundary:
            object.__setattr__(self, "boundary", f"livepeer-gateway-{uuid.uuid4().hex}")

    @property
    def content_type(self) -> str:
        return f"multipart/form-data; boundary={self.boundary}"


def _quote_param(value: str) -> str:
    # RFC 7578 §4.2: percent-encode the characters that would break the header.
    return value.replace("\\", "\\\\").replace('"', "%22").replace("\r", "%0D").replace("\n", "%0A")


def encode_multipart(body: MultipartBody) -> bytes:
    """Encode ``body`` as RFC 7578 ``multipart/form-data`` bytes."""
    delimiter = f"--{body.boundary}\r\n".encode()
    chunks: list[bytes] = []
    for name, value in body.fields.items():
        chunks.append(delimiter)
        chunks.append(
            f'Content-Disposition: form-data; name="{_quote_param(name)}"\r\n\r\n'.encode()
        )
        chunks.append(str(value).encode("utf-8"))
        chunks.append(b"\r\n")
    for part in body.files:
        chunks.append(delimiter)
        chunks.append(
            (
                f'Content-Disposition: form-data; name="{_quote_param(part.name)}"; '
                f'filename="{_quote_param(part.filename)}"\r\n'
                f"Content-Type: {part.content_type or 'application/octet-stream'}\r\n\r\n"
            ).encode()
        )
        chunks.append(bytes(part.content))
        chunks.append(b"\r\n")
    chunks.append(f"--{body.boundary}--\r\n".encode())
    return b"".join(chunks)
