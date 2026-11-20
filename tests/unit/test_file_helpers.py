from __future__ import annotations

import pytest

from app.models import AccessLevel
from app.services.files import sanitize_content_type, sanitize_filename
from app.services.storage import content_disposition


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\secret.txt", "secret.txt"),
        ("bad\x00name\x1f.txt", "badname.txt"),
        ("  .hidden. ", "hidden"),
        ("", "untitled"),
        (None, "untitled"),
        ("../", "untitled"),
        ("résumé.pdf", "résumé.pdf"),
    ],
)
def test_sanitize_filename(raw: str | None, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_sanitize_filename_truncates_but_keeps_extension() -> None:
    name = sanitize_filename("a" * 400 + ".tar.gz")
    assert len(name) <= 255
    assert name.endswith(".gz")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("text/plain", "text/plain"),
        ("text/html; charset=utf-8", "text/html"),
        ("IMAGE/PNG", "image/png"),
        ("", "application/octet-stream"),
        (None, "application/octet-stream"),
        ("not a type", "application/octet-stream"),
        ("text/plain\r\nX-Injected: 1", "application/octet-stream"),
    ],
)
def test_sanitize_content_type(raw: str | None, expected: str) -> None:
    assert sanitize_content_type(raw) == expected


def test_content_disposition_is_always_attachment_and_escaped() -> None:
    header = content_disposition('evil"name\\.html')
    assert header.startswith("attachment;")
    assert 'filename="evilname.html"' in header
    assert content_disposition("résumé.pdf").endswith("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf")
    assert 'filename="download"' in content_disposition("日本.")


def test_access_level_rank_order() -> None:
    assert AccessLevel.VIEWER.rank < AccessLevel.EDITOR.rank < AccessLevel.OWNER.rank
