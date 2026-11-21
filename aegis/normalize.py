"""Normalise untrusted text before every scan: Unicode compatibility folding,
invisible characters, look-alike letters, and encoded payloads (base64, hex,
URL-encoding, HTML entities) decoded to a FIXED depth. Over the size cap means
Hold, never skip."""
import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from . import config

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u2028\u2029"), None)

# common look-alike (homoglyph) folds, Cyrillic/Greek -> Latin
HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u03ba": "k", "\u03bd": "v",
    "\u0131": "i", "\u0261": "g", "\u01c3": "!", "\uff0e": ".", "\u2024": ".",
}

B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
DECODE_DEPTH = 3


def fold_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def strip_invisible(text: str) -> str:
    text = text.translate(ZERO_WIDTH)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def skeleton(text: str) -> str:
    """Case/space/punctuation-insensitive form, after compatibility folding.
    Used for canary and registered-secret matching (forwards and reversed)."""
    folded = unicodedata.normalize("NFKC", text).lower()
    return re.sub(r"[^a-z0-9]", "", folded)


def _printable_payload(raw: bytes):
    try:
        txt = raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    if not txt:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in txt)
    return txt if printable / len(txt) > 0.85 else None


def decode_b64_blobs(text: str) -> list:
    """Return decoded printable payloads of base64-looking blobs."""
    out = []
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        txt = _printable_payload(raw)
        if txt:
            out.append(txt)
    return out


def decode_hex_blobs(text: str) -> list:
    out = []
    for m in HEX_RE.finditer(text):
        try:
            raw = bytes.fromhex(m.group(0))
        except ValueError:
            continue
        txt = _printable_payload(raw)
        if txt:
            out.append(txt)
    return out


def _decode_layer(text: str) -> list:
    """One round of decoding: base64, hex, URL-encoding, HTML entities."""
    out = []
    out += decode_b64_blobs(text)
    out += decode_hex_blobs(text)
    for m in re.finditer(r"(?<![A-Z2-7])[A-Z2-7]{16,}={0,6}(?![A-Z2-7])", text):
        blob = m.group(0)
        try:
            txt = _printable_payload(base64.b32decode(blob + "=" * (-len(blob) % 8)))
        except (binascii.Error, ValueError):
            continue
        if txt:
            out.append(txt)
    for m in re.finditer(r"(?i)\b(base85|rot13)\s*[:=]\s*(\S{8,4096})", text):
        try:
            txt = (codecs.encode(m.group(2), "rot_13") if m.group(1).lower() == "rot13"
                   else _printable_payload(base64.b85decode(m.group(2))))
        except (binascii.Error, ValueError):
            continue
        if txt:
            out.append(txt)
    for m in re.finditer(r"(?i)\b(?:ASCII\s+)?decimal\s+bytes\s*[:=]\s*"
                         r"(\d{1,3}(?:\s*,\s*\d{1,3}){7,4095})(?!\d)", text):
        try:
            txt = _printable_payload(bytes(int(v) for v in m.group(1).split(",")))
        except ValueError:
            continue
        if txt:
            out.append(txt)
    for m in re.finditer(r"(?<!\w)1\s*=\s*[^;\n]{1,1024}"
                         r"(?:;\s*\d{1,2}\s*=\s*[^;\n]{1,1024}){1,19}", text):
        pieces = re.findall(r"(\d+)\s*=\s*([^;\n]+)", m.group(0))
        if [int(i) for i, _ in pieces] == list(range(1, len(pieces) + 1)):
            out.append("".join(value.strip() for _, value in pieces))
    escaped = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    if escaped != text:
        out.append(escaped)
    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        out.append(unquoted)
    unescaped = html.unescape(text)
    if unescaped != text:
        out.append(unescaped)
    return out


def normalize(text: str) -> dict:
    """Returns {clean, extra, oversize}. `extra` holds decoded payloads that
    must ALSO be scanned, to a fixed depth. Original text is never trusted."""
    oversize = len(text.encode("utf-8", "replace")) > config.MAX_CONTENT_BYTES
    clean = fold_homoglyphs(strip_invisible(unicodedata.normalize("NFKC", text)))
    if oversize:
        return {"clean": clean, "extra": [], "oversize": True, "had_invisible": clean != text}
    extra, seen = [], {clean}
    frontier = [clean]
    for _ in range(DECODE_DEPTH):
        next_frontier = []
        for variant in frontier:
            for decoded in _decode_layer(variant):
                decoded = fold_homoglyphs(strip_invisible(decoded))
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    extra.append(decoded)
                    next_frontier.append(decoded)
        frontier = next_frontier
        if not frontier:
            break
    return {"clean": clean, "extra": extra, "oversize": oversize,
            "had_invisible": clean != text or bool(extra)}


def scan_texts(text: str) -> list:
    """All text variants a detector must see."""
    n = normalize(text)
    return [n["clean"]] + n["extra"]