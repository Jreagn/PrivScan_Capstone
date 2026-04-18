from __future__ import annotations

import logging

try:
    from flask import Flask, request, jsonify
    from waitress import serve
except ImportError:
    request = None

    def jsonify(*args, **kwargs):
        if args and not kwargs:
            return args[0]
        return kwargs

    class Flask:  # type: ignore[override]
        def __init__(self, name):
            self.name = name
            self.config = {}
            self.logger = logging.getLogger(name)

        def route(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    def serve(*args, **kwargs):
        raise RuntimeError("waitress is unavailable in this environment")

from pathlib import Path
import base64
import csv
import io
import json
import os
import subprocess
import hashlib
import mimetypes
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 800 * 1024 * 1024 * 1024
app.logger.setLevel(logging.INFO)
CODE_VERSION = "2026-04-18-detection-gate-5"
CODE_SOURCE = str(Path(__file__).resolve())

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

OLLAMA_CONTAINER = os.environ.get("OLLAMA_CONTAINER", "ollama-server")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "privscan-8b-next")
OLLAMA_FALLBACK_MODEL = os.environ.get("OLLAMA_FALLBACK_MODEL", "privscan-8b").strip()
DETECTION_EVIDENCE_MODE = os.environ.get("DETECTION_EVIDENCE_MODE", "broad").strip().lower() or "broad"
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "3600"))
CONTEXT_MAX_BYTES = int(os.environ.get("CONTEXT_MAX_BYTES", "8192"))
CONTEXT_TAIL_BYTES = int(os.environ.get("CONTEXT_TAIL_BYTES", "2048"))
STRINGS_MIN_LEN = int(os.environ.get("STRINGS_MIN_LEN", "4"))
STRINGS_MAX_COUNT = int(os.environ.get("STRINGS_MAX_COUNT", "80"))
STRINGS_MAX_LEN = int(os.environ.get("STRINGS_MAX_LEN", "120"))
TEXT_EXCERPT_CHARS = int(os.environ.get("TEXT_EXCERPT_CHARS", "0"))
STRINGS_SCAN_CHUNK = int(os.environ.get("STRINGS_SCAN_CHUNK", "1048576"))
STRINGS_CARRY_BYTES = int(os.environ.get("STRINGS_CARRY_BYTES", "4096"))
OLLAMA_FAMILY_TIMEOUT = int(os.environ.get("OLLAMA_FAMILY_TIMEOUT", "420"))
OLLAMA_VERIFY_TIMEOUT = int(os.environ.get("OLLAMA_VERIFY_TIMEOUT", "900"))
OLLAMA_BROAD_TIMEOUT = int(os.environ.get("OLLAMA_BROAD_TIMEOUT", "300"))
CSV_ANALYSIS_ROWS = int(os.environ.get("CSV_ANALYSIS_ROWS", "60"))
CSV_HEAD_ROWS = int(os.environ.get("CSV_HEAD_ROWS", "6"))
CSV_TAIL_ROWS = int(os.environ.get("CSV_TAIL_ROWS", "6"))
CSV_MAX_COLUMNS = int(os.environ.get("CSV_MAX_COLUMNS", "16"))
CSV_MAX_CELL_LEN = int(os.environ.get("CSV_MAX_CELL_LEN", "80"))
CSV_SAMPLE_VALUES = int(os.environ.get("CSV_SAMPLE_VALUES", "8"))
CSV_DIGIT_SAMPLE = int(os.environ.get("CSV_DIGIT_SAMPLE", "32"))
CSV_TEXT_SAMPLE = int(os.environ.get("CSV_TEXT_SAMPLE", "24"))
DECODE_CANDIDATE_LIMIT = int(os.environ.get("DECODE_CANDIDATE_LIMIT", "16"))
ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")
COMMON_TEXT_BIGRAMS = (
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
    "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
)
FAMILY_VALIDATOR_THRESHOLDS = {
    "Binary or bit-pattern encoding in numeric values": 4,
    "Acrostic, initial, or ordered text-fragment encoding": 4,
    "Hidden timestamp or date encoding": 5,
    "Outlier row or extreme-value payload": 4,
    "Sequence or row-order anomaly": 4,
    "Cross-row text concatenation": 4,
    "Identifier-like or coordinate-like anomaly in numeric fields": 5,
    "Formula or executable-style payload": 5,
    "Whitespace or invisible-character encoding": 4,
    "Explicit character-code or encoded text payload": 5,
    "Byte-level or delimiter-level encoding": 4,
}
FAMILY_SHORT_CIRCUIT_THRESHOLDS = {
    "Binary or bit-pattern encoding in numeric values": 6,
    "Hidden timestamp or date encoding": 6,
    "Cross-row text concatenation": 6,
    "Identifier-like or coordinate-like anomaly in numeric fields": 6,
    "Formula or executable-style payload": 6,
    "Whitespace or invisible-character encoding": 6,
    "Explicit character-code or encoded text payload": 6,
}
SHORT_CIRCUIT_GAP = int(os.environ.get("CANDIDATE_SHORT_CIRCUIT_GAP", "2"))

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BRAILLE_SPINNER_RE = re.compile(r"[\u2800-\u28ff]")


def _clean_runtime_message(text: str, limit: int = 400) -> str:
    cleaned = _ANSI_ESCAPE_RE.sub("", text or "")
    cleaned = _BRAILLE_SPINNER_RE.sub(" ", cleaned)
    cleaned = _CONTROL_CHAR_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 3].rstrip() + "..."
    return cleaned


def _has_meaningful_runtime_text(text: str) -> bool:
    return bool(re.search(r"[A-Za-z0-9]{3,}", text or ""))


def _is_ollama_runner_failure(message: str) -> bool:
    cleaned = _clean_runtime_message(message).lower()
    return (
        "model runner has unexpectedly stopped" in cleaned
        or ("internal server error" in cleaned and "model runner" in cleaned)
        or ("post predict" in cleaned and "eof" in cleaned)
    )

KNOWN_TECHNIQUE_FAMILIES = [
    {
        "name": "Binary or bit-pattern encoding in numeric values",
        "priority": "decodable",
        "hint": "Look for consistent digits, parity, low-order bits, or repeated numeric-position patterns across any field or consecutive rows that may decode to text.",
    },
    {
        "name": "Acrostic, initial, or ordered text-fragment encoding",
        "priority": "textual",
        "hint": "Look for initials, leading letters, middle initials, case changes, or ordered text fragments across names, vendors, descriptions, or labels that spell hidden text.",
    },
    {
        "name": "Hidden timestamp or date encoding",
        "priority": "decodable",
        "hint": "Look for epoch timestamps, Excel serial dates, FILETIME values, or human-readable dates hidden in sparse columns, mismatched fields, or numeric outliers.",
    },
    {
        "name": "Outlier row or extreme-value payload",
        "priority": "structural",
        "hint": "Look for one or a few rows carrying extreme values, payload-like structure, or content inconsistent with surrounding rows.",
    },
    {
        "name": "Sequence or row-order anomaly",
        "priority": "structural",
        "hint": "Look for deliberate breaks in ordered IDs, dates, row positions, or grouped records that may signal hidden content.",
    },
    {
        "name": "Cross-row text concatenation",
        "priority": "decodable",
        "hint": "Look for fragments in descriptions, notes, labels, or repeated text fields that concatenate across rows into hidden words or instructions.",
    },
    {
        "name": "Identifier-like or coordinate-like anomaly in numeric fields",
        "priority": "structural",
        "hint": "Look for coordinates, phone-number-like values, or other real-world identifier formats appearing where business metrics should be.",
    },
    {
        "name": "Formula or executable-style payload",
        "priority": "decodable",
        "hint": "Look for spreadsheet formula syntax, executable expressions, or active payload text where static values should appear.",
    },
    {
        "name": "Whitespace or invisible-character encoding",
        "priority": "decodable",
        "hint": "Look for trailing spaces, invisible Unicode, or non-printing characters that vary systematically and may encode binary or text.",
    },
    {
        "name": "Explicit character-code or encoded text payload",
        "priority": "decodable",
        "hint": "Look for ASCII, base64, hex, or similar decodable payloads embedded in numbers, identifiers, or text fragments.",
    },
    {
        "name": "Byte-level or delimiter-level encoding",
        "priority": "decodable",
        "hint": "Look for raw-byte, delimiter, newline, or serialized-value patterns that may carry hidden binary content.",
    },
]

SPECIFIC_TECHNIQUE_PHRASES = [
    ("Latitude/longitude injected into numeric fields", "Identifier-like or coordinate-like anomaly in numeric fields"),
    ("Phone number format inserted into numeric field", "Identifier-like or coordinate-like anomaly in numeric fields"),
    ("Row moved to create sequence anomaly", "Sequence or row-order anomaly"),
    ("Outlier UNIX timestamp in numeric column", "Hidden timestamp or date encoding"),
    ("Excel serial date inserted", "Hidden timestamp or date encoding"),
    ("FILETIME value inserted", "Hidden timestamp or date encoding"),
    ("Hidden timestamp in far/unused column", "Hidden timestamp or date encoding"),
    ("Message appended across description field rows", "Cross-row text concatenation"),
    ("Acrostic initials across vendor names", "Acrostic, initial, or ordered text-fragment encoding"),
    ("Middle initials in surnames spell phrase", "Acrostic, initial, or ordered text-fragment encoding"),
    ("Capitalization pattern cue in text fields", "Acrostic, initial, or ordered text-fragment encoding"),
    ("Excel formula payload", "Formula or executable-style payload"),
    ("Trailing spaces encode binary", "Whitespace or invisible-character encoding"),
    ("Zero-width characters encode binary", "Whitespace or invisible-character encoding"),
    ("ASCII codes inserted into numeric column", "Explicit character-code or encoded text payload"),
    ("Base64 payload appended to IDs", "Explicit character-code or encoded text payload"),
    ("LSB-style bit encoding in newline bytes", "Byte-level or delimiter-level encoding"),
    ("Binary message embedded in account numbers", "Binary or bit-pattern encoding in numeric values"),
    ("Even/odd values encode binary", "Binary or bit-pattern encoding in numeric values"),
    ("LSB-style bit encoding in Volume column", "Binary or bit-pattern encoding in numeric values"),
]

_jobs_lock = threading.Lock()
_jobs: dict[str, dict] = {}

def _hex_preview(data: bytes, limit: int) -> str:
    if len(data) <= limit:
        return data.hex()
    return f"{data[:limit].hex()}...({len(data)} bytes total)"

def _extract_strings(data: bytes) -> list[str]:
    results: list[str] = []
    for match in re.finditer(rb"[ -~]{%d,}" % STRINGS_MIN_LEN, data):
        s = match.group(0).decode("ascii", errors="ignore")
        if len(s) > STRINGS_MAX_LEN:
            s = s[:STRINGS_MAX_LEN] + "..."
        results.append(s)
        if len(results) >= STRINGS_MAX_COUNT:
            break
    return results

def _extract_strings_stream(path: Path) -> list[str]:
    results: list[str] = []
    carry = b""
    ascii_re = re.compile(rb"[ -~]{%d,}" % STRINGS_MIN_LEN)
    utf16_re = re.compile(rb"(?:[ -~]\x00){%d,}" % STRINGS_MIN_LEN)

    with path.open("rb") as f:
        while True:
            chunk = f.read(STRINGS_SCAN_CHUNK)
            if not chunk:
                break
            buf = carry + chunk

            for match in ascii_re.finditer(buf):
                s = match.group(0).decode("ascii", errors="ignore")
                if len(s) > STRINGS_MAX_LEN:
                    s = s[:STRINGS_MAX_LEN] + "..."
                results.append(s)
                if len(results) >= STRINGS_MAX_COUNT:
                    return results

            for match in utf16_re.finditer(buf):
                raw = match.group(0)
                s = raw[::2].decode("ascii", errors="ignore")
                if len(s) > STRINGS_MAX_LEN:
                    s = s[:STRINGS_MAX_LEN] + "..."
                results.append(s)
                if len(results) >= STRINGS_MAX_COUNT:
                    return results

            carry = buf[-STRINGS_CARRY_BYTES:] if len(buf) > STRINGS_CARRY_BYTES else buf

    return results

def _compact_cell(value: str) -> str:
    cleaned = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(cleaned) > CSV_MAX_CELL_LEN:
        cleaned = cleaned[: CSV_MAX_CELL_LEN - 3].rstrip() + "..."
    return cleaned

def _looks_numeric(value: str) -> bool:
    return bool(re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value.strip()))

def _first_token_char(value: str) -> str:
    for char in value:
        if char.isalnum():
            return char
    return ""

def _printable_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return None
    text = "".join(ch for ch in text if ch == "\t" or ch == "\n" or 32 <= ord(ch) <= 126).strip()
    if len(text) < 4:
        return None
    if len(text) > 120:
        text = text[:117].rstrip() + "..."
    return text

def _looks_plausible_decoded_text(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 4:
        return False
    letter_count = sum(ch.isalpha() for ch in stripped)
    alnum_space_count = sum(ch.isalnum() or ch.isspace() or ch in {"_", "-", ":"} for ch in stripped)
    punctuation_count = sum(not (ch.isalnum() or ch.isspace()) for ch in stripped)
    if letter_count < 3:
        return False
    if alnum_space_count / max(len(stripped), 1) < 0.7:
        return False
    if punctuation_count / max(len(stripped), 1) > 0.25:
        return False
    return True


def _parse_coordinate_pair(text: str) -> tuple[float, float] | None:
    match = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*", text)
    if not match:
        return None
    first = float(match.group(1))
    second = float(match.group(2))
    valid_as_lat_lon = abs(first) <= 90 and abs(second) <= 180
    valid_as_lon_lat = abs(first) <= 180 and abs(second) <= 90
    if not (valid_as_lat_lon or valid_as_lon_lat):
        return None
    if abs(first - second) < 0.0001:
        return None
    return first, second


def _alpha_only(text: str) -> str:
    return "".join(ch for ch in str(text or "") if ch.isalpha())


def _common_bigram_hits(text: str) -> int:
    alpha = _alpha_only(text).upper()
    if len(alpha) < 4:
        return 0
    return sum(alpha.count(bigram) for bigram in COMMON_TEXT_BIGRAMS)


def _max_consonant_run(text: str) -> int:
    longest = 0
    current = 0
    for char in _alpha_only(text).upper():
        if char in "AEIOUY":
            current = 0
        else:
            current += 1
            longest = max(longest, current)
    return longest


def _score_initials_signal(text: str) -> int:
    cleaned = str(text or "").strip()
    alpha = _alpha_only(cleaned).upper()
    if len(alpha) < 4:
        return -40

    score = 0
    unique_chars = len(set(alpha))
    vowel_ratio = sum(ch in "AEIOUY" for ch in alpha) / max(len(alpha), 1)
    bigram_hits = _common_bigram_hits(alpha)

    if 0.22 <= vowel_ratio <= 0.68:
        score += 10
    else:
        score -= 12

    score += min(24, bigram_hits * 4)

    if _max_consonant_run(alpha) >= 5:
        score -= 20
    if unique_chars <= 4:
        score -= 18
    if re.fullmatch(r"[A-Z]+", cleaned) and bigram_hits == 0:
        score -= 16
    if re.fullmatch(r"[YNOPNA/ -]+", cleaned.upper()):
        score -= 28
    if cleaned.upper() in {"NOHIDDENDATA", "NONEFOUND"}:
        score -= 50

    return score


def _decode_numeric_datetime(value: str) -> tuple[str, str] | None:
    stripped = str(value or "").strip()
    if not re.fullmatch(r"[-+]?\d+(?:\.\d+)?", stripped):
        return None

    try:
        number = float(stripped)
    except ValueError:
        return None

    integer_text = stripped.lstrip("+-")
    integer_part = integer_text.split(".", 1)[0]

    def _format_candidate(label: str, dt: datetime) -> tuple[str, str] | None:
        if not (1970 <= dt.year <= 2100):
            return None
        return label, dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    if re.fullmatch(r"\d{10}", integer_part):
        dt = datetime.fromtimestamp(int(integer_part), tz=timezone.utc)
        return _format_candidate("unix timestamp", dt)

    if re.fullmatch(r"\d{13}", integer_part):
        dt = datetime.fromtimestamp(int(integer_part) / 1000.0, tz=timezone.utc)
        return _format_candidate("unix timestamp milliseconds", dt)

    if re.fullmatch(r"\d{17,18}", integer_part):
        try:
            filetime = int(integer_part)
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
            dt = epoch + timedelta(microseconds=filetime / 10)
            formatted = _format_candidate("FILETIME", dt)
            if formatted:
                return formatted
        except OverflowError:
            pass

    if re.fullmatch(r"\d{4,5}(?:\.\d+)?", integer_text) and 20000 <= number <= 80000:
        excel_epoch = datetime(1899, 12, 30, tzinfo=timezone.utc)
        dt = excel_epoch + timedelta(days=number)
        return _format_candidate("Excel serial date", dt)

    return None


def _normalize_phone_number(value: str) -> str | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return None
    if digits[0] in {"0", "1"} or digits[3] in {"0", "1"}:
        return None
    if len(set(digits)) <= 3:
        return None
    return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"


def _extract_middle_initial_payload(values: list[str]) -> str | None:
    initials: list[str] = []
    for value in values:
        parts = re.findall(r"[A-Za-z]+", str(value or ""))
        if len(parts) >= 3 and len(parts[1]) == 1:
            initials.append(parts[1].upper())
    candidate = "".join(initials)
    if len(candidate) < 4:
        return None
    if _score_initials_signal(candidate) < 18:
        return None
    return candidate


def _extract_cross_row_phrase(values: list[str]) -> str | None:
    fragments: list[str] = []
    for value in values:
        words = re.findall(r"[A-Za-z]{2,}", str(value or ""))
        if not words:
            continue
        fragment = words[0]
        if len(fragment) > 10:
            fragment = fragment[:10]
        fragments.append(fragment)
    if len(fragments) < 3:
        return None
    joined = "".join(fragments[:6])
    if _score_hidden_payload_text(joined) < 24:
        return None
    return joined


def _detect_sequence_anomaly(rows: list[dict[str, str]]) -> tuple[str, str] | None:
    if len(rows) < 3:
        return None
    columns = list(rows[0].keys())
    for column in columns[:4]:
        values = [str(row.get(column, "")).strip() for row in rows if str(row.get(column, "")).strip()]
        if len(values) < 3:
            continue
        if all(re.fullmatch(r"\d+", value) for value in values):
            numbers = [int(value) for value in values]
            is_increasing = all(b >= a for a, b in zip(numbers, numbers[1:]))
            is_decreasing = all(b <= a for a, b in zip(numbers, numbers[1:]))
            if not (is_increasing or is_decreasing):
                return column, ",".join(values[:6])
        parsed_dates: list[datetime] = []
        for value in values[:6]:
            try:
                parsed_dates.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
            except ValueError:
                parsed_dates = []
                break
        if len(parsed_dates) >= 3:
            timestamps = [item.timestamp() for item in parsed_dates]
            is_increasing = all(b >= a for a, b in zip(timestamps, timestamps[1:]))
            is_decreasing = all(b <= a for a, b in zip(timestamps, timestamps[1:]))
            if not (is_increasing or is_decreasing):
                return column, ",".join(values[:6])
    return None


def _family_validator_threshold(family: str) -> int:
    return FAMILY_VALIDATOR_THRESHOLDS.get(family, 4)


def _family_short_circuit_threshold(family: str) -> int:
    return FAMILY_SHORT_CIRCUIT_THRESHOLDS.get(family, 7)


def _candidate_display_value(item: dict) -> str:
    for key in ("decoded_candidate", "literal_payload"):
        value = str(item.get(key, "")).strip()
        if value and value.lower() not in {"none", "none found"}:
            return value
    return "none"


def _should_collect_initial(value: str) -> bool:
    stripped = str(value or "").strip()
    alpha = _alpha_only(stripped)
    if len(alpha) < 3:
        return False
    if stripped.lower() in {"y", "n", "yes", "no", "true", "false"}:
        return False
    return True


def _score_hidden_payload_text(text: str) -> int:
    cleaned = str(text or "").strip()
    if not cleaned or cleaned.lower() in {"none", "none found"}:
        return -100
    if _parse_coordinate_pair(cleaned):
        return 75

    score = 0
    letters = sum(ch.isalpha() for ch in cleaned)
    digits = sum(ch.isdigit() for ch in cleaned)
    spaces = sum(ch.isspace() for ch in cleaned)
    punctuation = sum(not (ch.isalnum() or ch.isspace()) for ch in cleaned)
    unique_chars = len(set(cleaned))

    if re.search(r"[A-Za-z]{4,}", cleaned):
        score += 45
    elif letters >= 3:
        score += 20

    if re.search(r"\b\d{4}-\d{2}-\d{2}\b", cleaned) or re.search(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", cleaned):
        score += 35
    if re.search(r"\b\d{3}[-.)\s]?\d{3}[-.\s]?\d{4}\b", cleaned):
        score += 30
    if re.search(r"\b[A-Z]{2,}(?:[_ -][A-Z0-9]{2,})+\b", cleaned):
        score += 25

    if 4 <= len(cleaned) <= 40:
        score += 10
    elif len(cleaned) > 80:
        score -= 10

    if letters and digits:
        score += 8
    if spaces:
        score += 6
    if punctuation <= max(len(cleaned) // 8, 1):
        score += 6
    else:
        score -= min(30, punctuation * 4)

    if unique_chars <= 2:
        score -= 45
    elif unique_chars <= 4:
        score -= 18

    alpha = _alpha_only(cleaned)
    if alpha and len(alpha) >= 6:
        if _common_bigram_hits(alpha) == 0:
            score -= 18
        if _max_consonant_run(alpha) >= 5:
            score -= 22
        if re.fullmatch(r"[A-Z0-9]+", cleaned) and " " not in cleaned and "_" not in cleaned and "-" not in cleaned:
            score -= 10

    if cleaned and max(cleaned.count(ch) for ch in set(cleaned)) / max(len(cleaned), 1) > 0.6:
        score -= 35

    if cleaned.upper() in {"NO HIDDEN DATA", "NONE FOUND"}:
        score -= 60

    if not letters and not _parse_coordinate_pair(cleaned):
        score -= 18

    return score


def _score_candidate_entry(item: dict) -> int:
    kind = str(item.get("kind", "")).strip()
    evidence = str(item.get("evidence", "")).strip()
    decoded = str(item.get("decoded_candidate", "none")).strip()
    literal = str(item.get("literal_payload", "none")).strip()
    validator_score = int(item.get("validator_score", 0) or 0)
    readability_score = int(item.get("readability_score", 0) or 0)
    score = validator_score * 14 + readability_score

    if decoded and decoded.lower() != "none":
        score += _score_hidden_payload_text(decoded)
    elif literal and literal.lower() != "none":
        score += _score_hidden_payload_text(literal)

    if "valid lat/lon pair" in evidence.lower():
        score += 55
    if "score " in evidence.lower():
        match = re.search(r"score\s+(-?\d+)", evidence, re.IGNORECASE)
        if match:
            score += int(match.group(1)) * 4

    kind_bonus = {
        "coordinate_pair_from_numeric_columns": 24,
        "timestamp_like": 22,
        "decoded_token": 18,
        "numeric_bitstream": 14,
        "text_initials": 10,
        "formula_like": 8,
        "whitespace_signal": 10,
        "byte_signal": 8,
        "phone_like": 12,
        "cross_row_text": 12,
        "middle_initial_phrase": 12,
        "sequence_anomaly": 12,
        "identifier_like": 6,
        "coordinate_like": 6,
        "numeric_pattern": -8,
        "metadata_comment": -12,
        "no_strong_candidates": -40,
    }
    score += kind_bonus.get(kind, 0)

    if decoded and decoded.lower() != "none" and _score_hidden_payload_text(decoded) < 10:
        score -= 18
    if kind == "text_initials":
        score += _score_initials_signal(decoded if decoded and decoded.lower() != "none" else evidence)
    if kind == "numeric_pattern" and "bitstream" not in evidence.lower():
        score -= 10
    if kind in {"coordinate_like", "identifier_like"} and validator_score < 4:
        score -= 16
    if kind == "metadata_comment":
        score -= 12

    return score


def _rank_hidden_data_values(values: list[str], limit: int = 3) -> list[str]:
    ranked = sorted(
        _dedupe_items(values, limit=max(limit * 4, 12)),
        key=lambda item: (-_score_hidden_payload_text(item), len(item), item),
    )
    filtered = [item for item in ranked if _score_hidden_payload_text(item) > -20]
    return filtered[:limit] if filtered else []

def _find_decodable_candidates(tokens: list[str]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        token = token.strip()
        if not token:
            continue

        if (
            re.fullmatch(r"[A-Za-z0-9+/=]{8,}", token)
            and len(token) % 4 == 0
            and any(ch.isdigit() or ch in "+/=" for ch in token)
            and any(ch.isalpha() for ch in token)
        ):
            try:
                decoded = base64.b64decode(token, validate=True)
            except Exception:
                decoded = None
            if decoded:
                text = _printable_text(decoded)
                if text and _looks_plausible_decoded_text(text):
                    entry = f"base64:{token[:32]} -> {text}"
                    if entry not in seen:
                        seen.add(entry)
                        candidates.append(entry)
                        if len(candidates) >= DECODE_CANDIDATE_LIMIT:
                            return candidates

        hex_token = token[2:] if token.lower().startswith("0x") else token
        if re.fullmatch(r"[0-9A-Fa-f]{8,}", hex_token) and len(hex_token) % 2 == 0:
            try:
                decoded = bytes.fromhex(hex_token)
            except Exception:
                decoded = None
            if decoded:
                text = _printable_text(decoded)
                if text and _looks_plausible_decoded_text(text):
                    entry = f"hex:{hex_token[:32]} -> {text}"
                    if entry not in seen:
                        seen.add(entry)
                        candidates.append(entry)
                        if len(candidates) >= DECODE_CANDIDATE_LIMIT:
                            return candidates
    return candidates

def _choose_csv_dialect(sample_text: str):
    non_comment_lines = [
        line for line in sample_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    candidate_line = non_comment_lines[0] if non_comment_lines else sample_text
    delimiters = [",", ";", "\t", "|"]
    delimiter = max(delimiters, key=lambda delim: candidate_line.count(delim))
    dialect = csv.excel
    dialect.delimiter = delimiter
    return dialect

def _build_csv_analysis_views(path: Path, strings_full: list[str]) -> dict:
    result = {
        "metadata_comment_lines": [],
        "column_names": [],
        "parsed_rows_head": [],
        "parsed_rows_tail": [],
        "numeric_last_digits_by_column": {},
        "text_initials_by_column": {},
        "text_samples_by_column": {},
        "candidate_decodings": [],
        "coordinate_candidates": [],
    }

    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            full_text = f.read()
            if not full_text.strip():
                return result

            comment_lines: list[str] = []
            non_comment_lines: list[str] = []
            for line in full_text.splitlines():
                if line.lstrip().startswith("#"):
                    if len(comment_lines) < 6:
                        comment_lines.append(_compact_cell(line))
                    continue
                if line.strip():
                    non_comment_lines.append(line)

            if not non_comment_lines:
                result["metadata_comment_lines"] = comment_lines
                return result

            dialect = _choose_csv_dialect("\n".join(non_comment_lines[:10]))
            parsed_rows = list(csv.reader(io.StringIO("\n".join(non_comment_lines)), dialect))
            if not parsed_rows:
                result["metadata_comment_lines"] = comment_lines
                return result

            header_row = parsed_rows[0]
            headers = [_compact_cell(cell) or f"col_{idx + 1}" for idx, cell in enumerate(header_row[:CSV_MAX_COLUMNS])]
            data_rows = parsed_rows[1:]

            sample_values: dict[str, list[str]] = {header: [] for header in headers}
            digit_sequences: dict[str, list[str]] = {header: [] for header in headers}
            initials_sequences: dict[str, list[str]] = {header: [] for header in headers}
            head_rows: list[dict[str, str]] = []
            tail_rows: deque[dict[str, str]] = deque(maxlen=CSV_TAIL_ROWS)
            candidate_tokens: list[str] = list(strings_full[:DECODE_CANDIDATE_LIMIT * 2])
            coordinate_candidates: list[dict[str, object]] = []
            lower_headers = {header.lower(): header for header in headers}
            for raw in data_rows[:CSV_ANALYSIS_ROWS]:
                row_map: dict[str, str] = {}
                for idx, header in enumerate(headers):
                    value = _compact_cell(raw[idx]) if idx < len(raw) else ""
                    row_map[header] = value
                    if value and len(sample_values[header]) < CSV_SAMPLE_VALUES:
                        sample_values[header].append(value)
                    if value and len(candidate_tokens) < DECODE_CANDIDATE_LIMIT * 8:
                        candidate_tokens.append(value)
                    if _looks_numeric(value):
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits and len("".join(digit_sequences[header])) < CSV_DIGIT_SAMPLE:
                            digit_sequences[header].append(digits[-1])
                    else:
                        initial = _first_token_char(value)
                        if initial and _should_collect_initial(value) and len("".join(initials_sequences[header])) < CSV_TEXT_SAMPLE:
                            initials_sequences[header].append(initial)

                numeric_pairs: list[tuple[str, float, str]] = []
                for header in headers:
                    if header.lower() in {"price", "date", "ticker"}:
                        continue
                    value = row_map.get(header, "")
                    if not value:
                        continue
                    try:
                        numeric_pairs.append((header, float(value), value))
                    except ValueError:
                        continue

                anomaly_bonus = 0
                low_header = lower_headers.get("low")
                high_header = lower_headers.get("high")
                open_header = lower_headers.get("open")
                close_header = lower_headers.get("close")
                try:
                    if low_header and high_header and open_header and close_header:
                        low_v = float(row_map.get(low_header, ""))
                        high_v = float(row_map.get(high_header, ""))
                        open_v = float(row_map.get(open_header, ""))
                        close_v = float(row_map.get(close_header, ""))
                        if low_v > min(open_v, close_v):
                            anomaly_bonus += 5
                        if high_v < max(open_v, close_v):
                            anomaly_bonus += 5
                        if low_v > high_v:
                            anomaly_bonus += 10
                except ValueError:
                    pass

                row_coordinate_candidates: list[dict[str, object]] = []
                for idx, (header_a, value_a, raw_a) in enumerate(numeric_pairs):
                    for header_b, value_b, raw_b in numeric_pairs[idx + 1:]:
                        pair_text = f"{raw_a}, {raw_b}"
                        if not _parse_coordinate_pair(pair_text):
                            continue
                        if not (
                            ("." in raw_a and len(raw_a.split(".")[-1]) >= 4)
                            or ("." in raw_b and len(raw_b.split(".")[-1]) >= 4)
                        ):
                            continue
                        if abs(value_a - value_b) < 0.0001:
                            continue
                        score = anomaly_bonus
                        if header_a.lower() in {"low", "close", "open", "high"}:
                            score += 1
                        if header_b.lower() in {"low", "close", "open", "high"}:
                            score += 1
                        if raw_a != raw_b:
                            score += 1
                        validity_label = "valid lat/lon pair"
                        row_coordinate_candidates.append(
                            {
                                "row_label": row_map.get("Price", row_map.get("Date", "unknown")),
                                "headers": f"{header_a}/{header_b}",
                                "pair": pair_text,
                                "score": score,
                                "validity": validity_label,
                            }
                        )
                if row_coordinate_candidates:
                    row_coordinate_candidates.sort(key=lambda item: (-int(item["score"]), str(item["headers"]), str(item["pair"])))
                    coordinate_candidates.append(row_coordinate_candidates[0])

                if len(head_rows) < CSV_HEAD_ROWS:
                    head_rows.append(row_map)
                tail_rows.append(row_map)

            result["metadata_comment_lines"] = comment_lines
            result["column_names"] = headers
            result["parsed_rows_head"] = head_rows
            result["parsed_rows_tail"] = list(tail_rows)
            result["numeric_last_digits_by_column"] = {
                header: "".join(values)
                for header, values in digit_sequences.items()
                if values
            }
            result["text_initials_by_column"] = {
                header: "".join(values)
                for header, values in initials_sequences.items()
                if values
            }
            result["text_samples_by_column"] = {
                header: values
                for header, values in sample_values.items()
                if values
            }
            result["candidate_decodings"] = _find_decodable_candidates(candidate_tokens)
            coordinate_candidates.sort(key=lambda item: (-int(item["score"]), str(item["row_label"]), str(item["headers"])))
            result["coordinate_candidates"] = coordinate_candidates[:8]
            trailing_space_counts = [
                len(line) - len(line.rstrip(" \t"))
                for line in non_comment_lines[:CSV_ANALYSIS_ROWS]
                if line.rstrip(" \t") != line
            ]
            zero_width_count = sum(full_text.count(char) for char in ZERO_WIDTH_CHARS)
            whitespace_signals: list[str] = []
            if trailing_space_counts:
                sample_counts = ",".join(str(count) for count in trailing_space_counts[:8])
                whitespace_signals.append(
                    f"data lines with trailing whitespace: {len(trailing_space_counts)} rows; trailing counts sample: {sample_counts}"
                )
            if zero_width_count:
                whitespace_signals.append(f"zero-width characters detected in file text: {zero_width_count}")
            result["whitespace_signals"] = whitespace_signals[:4]
            return result
    except Exception:
        app.logger.exception("Failed to build CSV analysis views for %s", path)
        return result

def build_file_context(path: Path) -> dict:
    size = path.stat().st_size
    sha256 = hashlib.sha256()
    head = b""
    tail = b""

    with path.open("rb") as f:
        head = f.read(CONTEXT_MAX_BYTES)
        if size > CONTEXT_TAIL_BYTES:
            f.seek(-CONTEXT_TAIL_BYTES, os.SEEK_END)
            tail = f.read(CONTEXT_TAIL_BYTES)
        f.seek(0)
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    mime, _ = mimetypes.guess_type(path.name)
    text_excerpt = ""
    if TEXT_EXCERPT_CHARS > 0:
        try:
            text_excerpt = head.decode("utf-8", errors="ignore")[:TEXT_EXCERPT_CHARS]
        except Exception:
            text_excerpt = ""

    strings_full = _extract_strings_stream(path)
    csv_views = _build_csv_analysis_views(path, strings_full)

    return {
        "filename": path.name,
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "mime_guess": mime or "unknown",
        "bytecode_head_hex": _hex_preview(head, CONTEXT_MAX_BYTES),
        "bytecode_tail_hex": _hex_preview(tail, CONTEXT_TAIL_BYTES) if tail else "",
        "strings_full": strings_full,
        "text_excerpt": text_excerpt,
        "metadata_comment_lines": csv_views["metadata_comment_lines"],
        "column_names": csv_views["column_names"],
        "parsed_rows_head": csv_views["parsed_rows_head"],
        "parsed_rows_tail": csv_views["parsed_rows_tail"],
        "numeric_last_digits_by_column": csv_views["numeric_last_digits_by_column"],
        "text_initials_by_column": csv_views["text_initials_by_column"],
        "text_samples_by_column": csv_views["text_samples_by_column"],
        "candidate_decodings": csv_views["candidate_decodings"],
        "coordinate_candidates": csv_views["coordinate_candidates"],
        "whitespace_signals": csv_views.get("whitespace_signals", []),
    }

def _decode_bitstream(bits: str, width: int) -> str | None:
    cleaned = "".join(ch for ch in bits if ch in "01")
    if len(cleaned) < width or len(cleaned) % width != 0:
        return None
    chars: list[str] = []
    for idx in range(0, len(cleaned), width):
        chunk = cleaned[idx : idx + width]
        value = int(chunk, 2)
        if not (32 <= value <= 126):
            return None
        chars.append(chr(value))
    text = "".join(chars).strip()
    return text if len(text) >= 2 else None

def _build_candidate_views(context: dict) -> list[dict]:
    candidates: list[dict] = []

    def add_candidate(
        kind: str,
        family_hint: str,
        evidence: str,
        decoded_candidate: str = "none",
        *,
        literal_payload: str = "none",
        validator_score: int = 0,
        readability_score: int | None = None,
        source_location: str = "unknown",
    ) -> None:
        evidence = str(evidence).strip()
        if not evidence:
            return
        decoded_candidate = str(decoded_candidate or "none").strip() or "none"
        literal_payload = str(literal_payload or "none").strip() or "none"
        if readability_score is None:
            display_value = decoded_candidate if decoded_candidate.lower() != "none" else literal_payload
            readability_score = _score_hidden_payload_text(display_value if display_value.lower() != "none" else evidence)
        entry = {
            "kind": kind,
            "family_hint": family_hint,
            "evidence": evidence[:220],
            "decoded_candidate": decoded_candidate[:120] if decoded_candidate.lower() != "none" else "none",
            "literal_payload": literal_payload[:120] if literal_payload.lower() != "none" else "none",
            "validator_score": max(0, int(validator_score)),
            "readability_score": int(readability_score),
            "source_location": str(source_location or "unknown")[:120],
        }
        entry["score"] = _score_candidate_entry(entry)
        if entry not in candidates:
            candidates.append(entry)

    for line in context.get("metadata_comment_lines", [])[:6]:
        inferred_family = _infer_specific_family([line]) or "Explicit character-code or encoded text payload"
        add_candidate(
            "metadata_comment",
            inferred_family,
            f"metadata comment present: {line}",
            line,
            literal_payload=line,
            validator_score=0,
            source_location="metadata comment",
        )

    for decoded in context.get("candidate_decodings", [])[:24]:
        literal = "none"
        if "->" in decoded:
            literal = decoded.split("->", 1)[0].split(":", 1)[-1].strip()
        add_candidate(
            "decoded_token",
            "Explicit character-code or encoded text payload",
            decoded,
            decoded.split("->", 1)[1].strip() if "->" in decoded else "none",
            literal_payload=literal,
            validator_score=6 if "->" in decoded else 3,
            source_location="decoded token scan",
        )

    seen_timestamp_evidence: set[str] = set()
    for column, values in context.get("text_samples_by_column", {}).items():
        if re.search(r"(date|time|year|month|day)", column, re.IGNORECASE):
            continue
        for value in values[:6]:
            decoded_timestamp = _decode_numeric_datetime(value)
            if not decoded_timestamp:
                continue
            label, human_value = decoded_timestamp
            evidence = f"{column} contains {label}-like value: {value} -> {human_value}"
            if evidence in seen_timestamp_evidence:
                continue
            seen_timestamp_evidence.add(evidence)
            add_candidate(
                "timestamp_like",
                "Hidden timestamp or date encoding",
                evidence,
                human_value,
                literal_payload=value,
                validator_score=7,
                source_location=f"{column} field",
            )

    for item in context.get("coordinate_candidates", [])[:8]:
        row_label = str(item.get("row_label", "unknown")).strip() or "unknown"
        headers = str(item.get("headers", "")).strip()
        pair = str(item.get("pair", "")).strip()
        validity = str(item.get("validity", "")).strip()
        score = int(item.get("score", 0) or 0)
        if pair:
            add_candidate(
                "coordinate_pair_from_numeric_columns",
                "Identifier-like or coordinate-like anomaly in numeric fields",
                f"row {row_label} has {validity or 'coordinate-like pair'} in {headers}: {pair} (score {score})",
                pair if validity.startswith("valid") else "none",
                literal_payload=pair,
                validator_score=6 + min(score, 3),
                source_location=f"row {row_label} {headers}",
            )

    for column, digits in context.get("numeric_last_digits_by_column", {}).items():
        if not digits:
            continue
        parity_bits = "".join(str(int(ch) % 2) for ch in digits if ch.isdigit())
        direct_bits = "".join(ch for ch in digits if ch in "01")
        decoded_any = False
        for label, bitstream in (("direct", direct_bits), ("parity", parity_bits)):
            for width in (8, 7):
                decoded = _decode_bitstream(bitstream, width)
                if decoded:
                    decoded_any = True
                    add_candidate(
                        "numeric_bitstream",
                        "Binary or bit-pattern encoding in numeric values",
                        f"{column} {label} bitstream: {bitstream[:64]}",
                        decoded,
                        literal_payload=bitstream[:64],
                        validator_score=6,
                        source_location=f"{column} last digits",
                    )
        if decoded_any or len(set(digits)) <= 2:
            add_candidate(
                "numeric_pattern",
                "Binary or bit-pattern encoding in numeric values",
                f"{column} last digits sequence: {digits[:64]}",
                literal_payload=digits[:64],
                validator_score=2 if decoded_any else 1,
                source_location=f"{column} last digits",
            )

    for column, initials in context.get("text_initials_by_column", {}).items():
        if initials:
            initials_score = _score_initials_signal(initials)
            add_candidate(
                "text_initials",
                "Acrostic, initial, or ordered text-fragment encoding",
                f"{column} initials sequence: {initials[:64]}",
                initials[:64] if initials_score >= 12 else "none",
                literal_payload=initials[:64],
                validator_score=4 if initials_score >= 18 else 1,
                readability_score=initials_score,
                source_location=f"{column} initials",
            )

    for column, values in context.get("text_samples_by_column", {}).items():
        middle_initial_payload = _extract_middle_initial_payload(values[:8])
        if middle_initial_payload:
            add_candidate(
                "middle_initial_phrase",
                "Acrostic, initial, or ordered text-fragment encoding",
                f"{column} middle-initial sequence: {middle_initial_payload}",
                middle_initial_payload,
                literal_payload=middle_initial_payload,
                validator_score=6,
                source_location=f"{column} names",
            )

        cross_row_payload = _extract_cross_row_phrase(values[:8])
        if cross_row_payload:
            add_candidate(
                "cross_row_text",
                "Cross-row text concatenation",
                f"{column} row fragments concatenate to: {cross_row_payload}",
                cross_row_payload,
                literal_payload=cross_row_payload,
                validator_score=5,
                source_location=f"{column} row fragments",
            )

        for value in values[:6]:
            stripped = str(value).strip()
            if not stripped:
                continue
            looks_plain_number = bool(re.fullmatch(r"[-+]?\d+(?:\.\d+)?", stripped))
            if stripped.startswith(("=", "@")) or ((stripped.startswith(("+", "-"))) and not looks_plain_number):
                add_candidate(
                    "formula_like",
                    "Formula or executable-style payload",
                    f"{column} contains formula-like value: {stripped}",
                    stripped,
                    literal_payload=stripped,
                    validator_score=7,
                    source_location=f"{column} field",
                )
            phone_value = _normalize_phone_number(stripped)
            if phone_value:
                add_candidate(
                    "phone_like",
                    "Identifier-like or coordinate-like anomaly in numeric fields",
                    f"{column} contains phone-number-like value: {stripped} -> {phone_value}",
                    phone_value,
                    literal_payload=stripped,
                    validator_score=7,
                    source_location=f"{column} field",
                )
            elif re.fullmatch(r"-?\d{10,}", stripped):
                add_candidate(
                    "identifier_like",
                    "Identifier-like or coordinate-like anomaly in numeric fields",
                    f"{column} contains long identifier-like value: {stripped}",
                    stripped,
                    literal_payload=stripped,
                    validator_score=2,
                    source_location=f"{column} field",
                )
            if re.fullmatch(r"-?\d+\.\d+,\s*-?\d+\.\d+", stripped):
                parsed_pair = _parse_coordinate_pair(stripped)
                add_candidate(
                    "coordinate_like",
                    "Identifier-like or coordinate-like anomaly in numeric fields",
                    f"{column} contains coordinate-like pair: {stripped}",
                    stripped if parsed_pair else "none",
                    literal_payload=stripped,
                    validator_score=6 if parsed_pair else 1,
                    source_location=f"{column} field",
                )

    for signal in context.get("whitespace_signals", [])[:4]:
        family = "Whitespace or invisible-character encoding"
        kind = "whitespace_signal"
        if "newline" in signal.lower() or "byte" in signal.lower():
            family = "Byte-level or delimiter-level encoding"
            kind = "byte_signal"
        add_candidate(
            kind,
            family,
            signal,
            literal_payload=signal,
            validator_score=5 if "zero-width" in signal.lower() else 4,
            source_location="whitespace scan",
        )

    sequence_anomaly = _detect_sequence_anomaly(context.get("parsed_rows_head", []) + context.get("parsed_rows_tail", []))
    if sequence_anomaly:
        column, sequence_preview = sequence_anomaly
        add_candidate(
            "sequence_anomaly",
            "Sequence or row-order anomaly",
            f"{column} shows non-monotonic order in sampled rows: {sequence_preview}",
            literal_payload=sequence_preview,
            validator_score=5,
            source_location=f"{column} sampled rows",
        )

    if not candidates:
        add_candidate(
            "no_strong_candidates",
            "none",
            "No strong precomputed candidates were extracted from metadata, decoded tokens, numeric bitstreams, or text initials.",
            validator_score=0,
            source_location="candidate summary",
        )

    candidates.sort(
        key=lambda item: (
            -int(item.get("score", 0) or 0),
            str(item.get("family_hint", "")),
            str(item.get("evidence", "")),
        )
    )
    return candidates[:24]

def _select_candidate_review_items(candidates: list[dict], max_families: int = 2, max_items: int = 2) -> list[dict]:
    selected: list[dict] = []
    families_seen: list[str] = []
    per_family_counts: dict[str, int] = {}

    for item in candidates:
        family = str(item.get("family_hint", "")).strip() or "none"
        if family not in families_seen:
            if len(families_seen) >= max_families:
                continue
            families_seen.append(family)
        count = per_family_counts.get(family, 0)
        if count >= 1:
            continue
        selected.append(item)
        per_family_counts[family] = count + 1
        if len(selected) >= max_items:
            break

    if selected:
        return selected
    return candidates[:max_items]


def _build_ranked_candidate_review_payload(candidates: list[dict], max_families: int = 6, max_items_per_family: int = 3) -> dict:
    families: dict[str, list[dict]] = {}
    for item in candidates:
        family = str(item.get("family_hint", "")).strip() or "none"
        families.setdefault(family, []).append(item)

    family_summaries: list[dict] = []
    for family, family_items in families.items():
        ranked_items = sorted(
            family_items,
            key=lambda item: (-int(item.get("score", 0) or 0), str(item.get("kind", "")), str(item.get("evidence", ""))),
        )
        decoded_candidates = _rank_hidden_data_values(
            [
                str(item.get("decoded_candidate", "")).strip()
                for item in ranked_items
                if str(item.get("decoded_candidate", "")).strip().lower() not in {"", "none", "none found"}
            ],
            limit=3,
        )
        family_summaries.append(
            {
                "family": family,
                "best_score": int(ranked_items[0].get("score", 0) or 0),
                "best_validator_score": int(ranked_items[0].get("validator_score", 0) or 0),
                "best_readability_score": int(ranked_items[0].get("readability_score", 0) or 0),
                "candidate_count": len(ranked_items),
                "top_evidence": [str(item.get("evidence", "")).strip() for item in ranked_items[:max_items_per_family] if str(item.get("evidence", "")).strip()],
                "decoded_candidates": decoded_candidates or "none",
            }
        )

    family_summaries.sort(
        key=lambda item: (
            -int(item.get("best_validator_score", 0) or 0),
            -int(item.get("best_readability_score", 0) or 0),
            -int(item.get("best_score", 0) or 0),
            item.get("family") == "none",
            str(item.get("family", "")),
        )
    )
    ranked_candidates = [
        {
            "family": str(item.get("family_hint", "")).strip() or "none",
            "kind": str(item.get("kind", "")).strip(),
            "score": int(item.get("score", 0) or 0),
            "validator_score": int(item.get("validator_score", 0) or 0),
            "readability_score": int(item.get("readability_score", 0) or 0),
            "evidence": str(item.get("evidence", "")).strip(),
            "decoded_candidate": str(item.get("decoded_candidate", "none")).strip() or "none",
            "literal_payload": str(item.get("literal_payload", "none")).strip() or "none",
            "source_location": str(item.get("source_location", "unknown")).strip() or "unknown",
        }
        for item in candidates[: max_families * max_items_per_family]
    ]
    return {
        "family_summaries": family_summaries[:max_families],
        "ranked_candidates": ranked_candidates,
    }


def _prune_candidates_for_review(candidates: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for item in candidates:
        family = str(item.get("family_hint", "")).strip() or "none"
        grouped.setdefault(family, []).append(item)

    kept: list[dict] = []
    for family, family_items in grouped.items():
        ranked_items = sorted(
            family_items,
            key=lambda item: (
                -int(item.get("validator_score", 0) or 0),
                -int(item.get("readability_score", 0) or 0),
                -int(item.get("score", 0) or 0),
                str(item.get("kind", "")),
                str(item.get("evidence", "")),
            ),
        )
        threshold = _family_validator_threshold(family)
        kept_items = [
            item for item in ranked_items
            if family == "none"
            or int(item.get("validator_score", 0) or 0) >= threshold
        ]
        if not kept_items and family != "none":
            continue
        kept.extend(kept_items[:3])

    if not kept:
        kept = candidates[:6]

    kept.sort(
        key=lambda item: (
            -int(item.get("validator_score", 0) or 0),
            -int(item.get("readability_score", 0) or 0),
            -int(item.get("score", 0) or 0),
            str(item.get("family_hint", "")),
            str(item.get("evidence", "")),
        )
    )
    return kept[:12]


def _deterministic_candidate_decision(context: dict, candidates: list[dict]) -> dict | None:
    if not candidates:
        return None

    payload = _build_ranked_candidate_review_payload(candidates, max_families=4, max_items_per_family=2)
    family_summaries = [
        item for item in payload.get("family_summaries", [])
        if str(item.get("family", "")).strip() not in {"", "none", "none found"}
    ]
    if not family_summaries:
        return None

    top = family_summaries[0]
    runner_up = family_summaries[1] if len(family_summaries) > 1 else None
    family = str(top.get("family", "")).strip()
    top_validator = int(top.get("best_validator_score", 0) or 0)
    top_readability = int(top.get("best_readability_score", 0) or 0)
    runner_validator = int(runner_up.get("best_validator_score", 0) or 0) if runner_up else 0

    if top_validator < _family_short_circuit_threshold(family):
        return None
    if runner_up and (top_validator - runner_validator) < SHORT_CIRCUIT_GAP:
        return None
    if top_readability < 10 and family not in {
        "Identifier-like or coordinate-like anomaly in numeric fields",
        "Hidden timestamp or date encoding",
        "Formula or executable-style payload",
    }:
        return None

    matching_candidates = [
        item for item in candidates
        if str(item.get("family_hint", "")).strip() == family
    ]
    hidden_values = _rank_hidden_data_values(
        [
            _candidate_display_value(item)
            for item in matching_candidates
            if _candidate_display_value(item).lower() not in {"none", "none found"}
        ],
        limit=3,
    )
    evidence = _dedupe_items(
        [
            str(item.get("evidence", "")).strip()
            for item in matching_candidates[:3]
            if str(item.get("evidence", "")).strip()
        ] + ["deterministic validator short-circuit selected the strongest candidate slate"],
        limit=3,
    )

    return {
        "summary": "Financial or ledger-style tabular data.",
        "anomalies": _canonical_anomalies_for_family(family) or "none found",
        "hidden_indicators": _dedupe_items(
            [
                f"candidate family flagged: {family}",
                _canonical_indicator_for_family(family),
            ],
            limit=3,
        ),
        "hidden_data": hidden_values if hidden_values else "none",
        "evidence": evidence or "none found",
    }

def _extract_json_payload(output: str) -> dict | None:
    output = output.strip()
    if output.startswith("```"):
        output = re.sub(r"^```(?:json)?\s*", "", output)
        output = re.sub(r"\s*```$", "", output)

    candidates = [output]
    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.append(output[start : end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None

def _extract_loose_family_payload(output: str) -> dict | None:
    text = output.strip()
    if not text:
        return None

    summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text, re.DOTALL)
    family_match = re.search(r'"family"\s*:\s*"([^"]*)"', text, re.DOTALL)
    match_match = re.search(r'"match"\s*:\s*"([^"]*)"', text, re.DOTALL)
    evidence_match = re.search(r'"evidence"\s*:\s*"([^"]*)"', text, re.DOTALL)
    decoded_match = re.search(r'"decoded_candidate"\s*:\s*"([^"]*)"', text, re.DOTALL)
    candidate_match = re.search(r'"candidate_families"\s*:\s*(\[[^\]]*\]|"[^"]*")', text, re.DOTALL)
    evidence_array_match = re.search(r'"evidence"\s*:\s*(\[[^\]]*\])', text, re.DOTALL)

    if not family_match and not candidate_match and not summary_match:
        return None

    candidate_families = "none found"
    if candidate_match:
        raw_candidates = candidate_match.group(1).strip()
        try:
            candidate_families = json.loads(raw_candidates)
        except json.JSONDecodeError:
            candidate_families = raw_candidates.strip('"')

    evidence_value: list[str] | str = "none found"
    if evidence_array_match:
        raw_evidence = evidence_array_match.group(1).strip()
        try:
            loaded_evidence = json.loads(raw_evidence)
            if isinstance(loaded_evidence, list) and loaded_evidence:
                evidence_value = [str(item) for item in loaded_evidence]
        except json.JSONDecodeError:
            pass

    family_checks: list[dict] | str = "none found"
    if family_match:
        family_checks = [
            {
                "family": family_match.group(1).strip() or "unknown",
                "match": (match_match.group(1).strip().lower() if match_match else "uncertain") or "uncertain",
                "evidence": (evidence_match.group(1).strip() if evidence_match else "none found") or "none found",
                "decoded_candidate": (decoded_match.group(1).strip() if decoded_match else "none") or "none",
            }
        ]

    return {
        "summary": (summary_match.group(1).strip() if summary_match else "Financial or ledger-style tabular data.") or "Financial or ledger-style tabular data.",
        "family_checks": family_checks,
        "candidate_families": candidate_families,
        "evidence": evidence_value,
        "raw_model_output": output if output else "",
    }

def _extract_loose_candidate_payload(output: str) -> dict | None:
    text = output.strip()
    if not text:
        return None

    summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text, re.DOTALL)
    likely_families_match = re.search(r'"likely_families"\s*:\s*(\[[^\]]*\]|"[^"]*")', text, re.DOTALL)
    family_matches = re.findall(r'"family"\s*:\s*"([^"]*)"', text, re.DOTALL)
    confidence_matches = re.findall(r'"confidence"\s*:\s*"([^"]*)"', text, re.DOTALL)
    indicator_matches = re.findall(r'"indicator"\s*:\s*"([^"]*)"', text, re.DOTALL)
    hidden_data_matches = re.findall(r'"hidden_data"\s*:\s*"([^"]*)"', text, re.DOTALL)
    evidence_matches = re.findall(r'"evidence"\s*:\s*(\[[^\]]*\]|"[^"]*")', text, re.DOTALL)

    if not summary_match and not family_matches and not likely_families_match:
        return None

    likely_families: list[str] | str = "none found"
    if likely_families_match:
        raw_likely = likely_families_match.group(1).strip()
        try:
            loaded = json.loads(raw_likely)
            if isinstance(loaded, list):
                likely_families = [str(item).strip() for item in loaded if str(item).strip()] or "none found"
            elif isinstance(loaded, str) and loaded.strip():
                likely_families = [loaded.strip()]
        except json.JSONDecodeError:
            cleaned = raw_likely.strip('"')
            likely_families = [cleaned] if cleaned else "none found"

    ranked_findings: list[dict] = []
    max_len = max(
        len(family_matches),
        len(confidence_matches),
        len(indicator_matches),
        len(hidden_data_matches),
        len(evidence_matches),
        0,
    )
    for idx in range(max_len):
        family = family_matches[idx].strip() if idx < len(family_matches) else "none found"
        confidence = confidence_matches[idx].strip() if idx < len(confidence_matches) else "none"
        indicator = indicator_matches[idx].strip() if idx < len(indicator_matches) else "none found"
        hidden_data = hidden_data_matches[idx].strip() if idx < len(hidden_data_matches) else "none"
        evidence_value: list[str] | str = "none found"
        if idx < len(evidence_matches):
            raw_evidence = evidence_matches[idx].strip()
            try:
                loaded = json.loads(raw_evidence)
                if isinstance(loaded, list):
                    evidence_value = [str(item).strip() for item in loaded if str(item).strip()] or "none found"
                elif isinstance(loaded, str) and loaded.strip():
                    evidence_value = [loaded.strip()]
            except json.JSONDecodeError:
                cleaned = raw_evidence.strip('"')
                if cleaned:
                    evidence_value = [cleaned]
        ranked_findings.append(
            {
                "family": family or "none found",
                "confidence": confidence or "none",
                "indicator": indicator or "none found",
                "hidden_data": hidden_data or "none",
                "evidence": evidence_value,
            }
        )

    return {
        "summary": (summary_match.group(1).strip() if summary_match else "Financial or ledger-style tabular data.") or "Financial or ledger-style tabular data.",
        "ranked_findings": ranked_findings[:3] or [{"family": "none found", "confidence": "none", "indicator": "none found", "hidden_data": "none", "evidence": "none found"}],
        "likely_families": likely_families,
        "raw_model_output": output if output else "",
    }

def _normalize_list_field(value, default: str) -> list[str] | str:
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return default
        if cleaned.lower() in {"none", "none found"}:
            return "none found"
        return [cleaned]
    if isinstance(value, list):
        cleaned_items = [str(item).strip() for item in value if str(item).strip()]
        if not cleaned_items:
            return default
        return cleaned_items
    return default

def _dedupe_items(items: list[str], limit: int = 12) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        cleaned = str(item).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
        if len(deduped) >= limit:
            break
    return deduped

def _infer_specific_family(clues: list[str]) -> str | None:
    combined = " \n".join(str(item) for item in clues if str(item).strip())
    if not combined:
        return None
    for phrase, family in SPECIFIC_TECHNIQUE_PHRASES:
        if phrase.lower() in combined.lower():
            return family
    for family in (item["name"] for item in KNOWN_TECHNIQUE_FAMILIES):
        if family.lower() in combined.lower():
            return family
    return None

def _extract_specific_families(clues: list[str]) -> list[str]:
    combined = " \n".join(str(item) for item in clues if str(item).strip())
    if not combined:
        return []
    families: list[str] = []
    for phrase, family in SPECIFIC_TECHNIQUE_PHRASES:
        if phrase.lower() in combined.lower():
            families.append(family)
    for family in (item["name"] for item in KNOWN_TECHNIQUE_FAMILIES):
        if family.lower() in combined.lower():
            families.append(family)
    return _dedupe_items(families, limit=6)

def _canonical_anomalies_for_family(family: str | None) -> list[str]:
    if family == "Identifier-like or coordinate-like anomaly in numeric fields":
        return ["coordinate-like or identifier-like values injected into numeric fields"]
    if family == "Hidden timestamp or date encoding":
        return ["timestamp-like or date-like values injected into non-date fields"]
    if family == "Binary or bit-pattern encoding in numeric values":
        return ["bit-pattern or parity-like encoding detected in numeric values"]
    if family == "Acrostic, initial, or ordered text-fragment encoding":
        return ["ordered text fragments or initials appear to encode hidden content"]
    if family == "Cross-row text concatenation":
        return ["cross-row text fragments appear to concatenate into hidden content"]
    if family == "Formula or executable-style payload":
        return ["formula-like or executable-style payload detected in value fields"]
    if family == "Whitespace or invisible-character encoding":
        return ["whitespace or invisible-character encoding pattern detected"]
    if family == "Explicit character-code or encoded text payload":
        return ["encoded text or character-code payload detected in visible fields"]
    if family == "Byte-level or delimiter-level encoding":
        return ["byte-level or delimiter-level anomaly suggests hidden payload"]
    if family == "Outlier row or extreme-value payload":
        return ["outlier row or extreme-value payload detected"]
    if family == "Sequence or row-order anomaly":
        return ["row order or sequence anomaly suggests hidden signaling"]
    return []

def _canonical_indicator_for_family(family: str | None) -> str:
    if family == "Identifier-like or coordinate-like anomaly in numeric fields":
        return "known-technique name: Latitude/longitude injected into numeric fields"
    if family == "Hidden timestamp or date encoding":
        return "known-technique name: Hidden timestamp or date encoding"
    if family == "Binary or bit-pattern encoding in numeric values":
        return "known-technique name: Binary or bit-pattern encoding in numeric values"
    if family == "Acrostic, initial, or ordered text-fragment encoding":
        return "known-technique name: Acrostic, initial, or ordered text-fragment encoding"
    if family == "Cross-row text concatenation":
        return "known-technique name: Cross-row text concatenation"
    if family == "Formula or executable-style payload":
        return "known-technique name: Formula or executable-style payload"
    if family == "Whitespace or invisible-character encoding":
        return "known-technique name: Whitespace or invisible-character encoding"
    if family == "Explicit character-code or encoded text payload":
        return "known-technique name: Explicit character-code or encoded text payload"
    if family == "Byte-level or delimiter-level encoding":
        return "known-technique name: Byte-level or delimiter-level encoding"
    if family == "Outlier row or extreme-value payload":
        return "known-technique name: Outlier row or extreme-value payload"
    if family == "Sequence or row-order anomaly":
        return "known-technique name: Sequence or row-order anomaly"
    return ""


def _generic_detection_evidence_for_family(family: str | None) -> list[str]:
    canonical = _canonical_anomalies_for_family(family)
    if canonical:
        return [
            canonical[0],
            "the pattern is stronger than ordinary formatting or business-data variation",
        ]
    return [
        "multiple cues suggest intentional hidden signaling",
        "the pattern is stronger than ordinary formatting or business-data variation",
    ]


GENERIC_DETECTION_EVIDENCE = {
    "multiple cues suggest intentional hidden signaling",
    "the pattern is stronger than ordinary formatting or business-data variation",
}


CANONICAL_DETECTION_EVIDENCE = {
    clue.lower()
    for family in (item["name"] for item in KNOWN_TECHNIQUE_FAMILIES)
    for clue in _canonical_anomalies_for_family(family)
}


DETECTION_META_EVIDENCE_PREFIXES = (
    "hidden-presence detection ",
    "candidate review ",
    "primary detection model ",
    "fallback detection model ",
)


def _is_boilerplate_detection_clue(clue: str) -> bool:
    normalized = clue.strip().lower()
    if not normalized:
        return True
    if normalized in GENERIC_DETECTION_EVIDENCE:
        return True
    if normalized in CANONICAL_DETECTION_EVIDENCE:
        return True
    return normalized.startswith(DETECTION_META_EVIDENCE_PREFIXES)


def _detection_clues_from_result(parsed: dict) -> list[str]:
    clues: list[str] = []
    for field_name in (
        "selected_indicator_phrase",
        "hidden_indicators",
        "anomalies",
        "evidence",
        "summary",
    ):
        value = parsed.get(field_name, "none found")
        if isinstance(value, list):
            clues.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip():
            clues.append(value.strip())
    return clues


def _clue_has_specific_locator(clue: str) -> bool:
    normalized = clue.strip().lower()
    if not normalized:
        return False

    locator_patterns = (
        r"\brow(?:s)?\s+\d+",
        r'\bcolumn(?:s)?\s+[\'"`a-z0-9_]+',
        r'\bfield(?:s)?\s+[\'"`][^\'"`]+[\'"`]',
        r'\bvalue(?:s)?\s+[\'"`][^\'"`]+[\'"`]',
        r"\bcell\s+[a-z]+\d+",
        r"\b(?:offset|index|count|length|position)\s+\d+",
        r'\b(?:decoded|concatenated|joined)\s+(?:text|string|token|fragment)s?\s+[\'"`][^\'"`]+[\'"`]',
    )
    if any(re.search(pattern, normalized) for pattern in locator_patterns):
        return True

    anchored_terms = ("row", "rows", "column", "columns", "field", "fields", "value", "values", "cell")
    return any(term in normalized for term in anchored_terms) and bool(re.search(r"\d", normalized))



def _has_concrete_hidden_presence_evidence(parsed: dict, family: str | None) -> bool:
    hidden_data = str(parsed.get("hidden_data", "")).strip().lower()
    if hidden_data and hidden_data not in {"none", "none found"}:
        return True

    clues = _detection_clues_from_result(parsed)
    material_clues = [clue for clue in clues if not _is_boilerplate_detection_clue(clue)]

    if DETECTION_EVIDENCE_MODE == "broad":
        concrete_markers = (
            "row ",
            "rows ",
            "column ",
            "columns ",
            "field ",
            "fields ",
            "value ",
            "values ",
            "coordinate",
            "latitude",
            "longitude",
            "timestamp",
            "date-like",
            "calendar date",
            "binary",
            "bit-pattern",
            "parity",
            "acrostic",
            "initial",
            "concatenate",
            "cross-row",
            "fragment",
            "fragments",
            "formula",
            "executable",
            "whitespace",
            "invisible",
            "zero-width",
            "encoded text",
            "character-code",
            "byte-level",
            "delimiter",
            "outlier",
            "sequence",
            "identifier-like",
            "decoded",
            "decode",
        )
        return any(
            marker in clue.lower()
            for clue in material_clues
            for marker in concrete_markers
        )

    anchored_clues = [clue for clue in material_clues if _clue_has_specific_locator(clue)]
    return bool(anchored_clues)


def _field_has_signal(value) -> bool:
    if isinstance(value, list):
        return any(str(item).strip().lower() not in {"", "none", "none found"} for item in value)
    return str(value or "").strip().lower() not in {"", "none", "none found"}


def _detect_family_from_output(parsed: dict) -> str | None:
    selected_family = str(parsed.get("selected_family", "")).strip()
    if selected_family and selected_family != "none found":
        return selected_family

    candidate_families = parsed.get("candidate_families", "none found")
    if isinstance(candidate_families, list):
        for item in candidate_families:
            family = str(item).strip()
            if family and family != "none found":
                return family
    elif isinstance(candidate_families, str) and candidate_families.strip() not in {"", "none", "none found"}:
        return candidate_families.strip()

    family_checks = parsed.get("family_checks", [])
    if isinstance(family_checks, list):
        for item in family_checks:
            if not isinstance(item, dict):
                continue
            if str(item.get("match", "")).strip().lower() == "yes":
                family = str(item.get("family", "")).strip()
                if family:
                    return family

    ranked_findings = parsed.get("ranked_findings", [])
    if isinstance(ranked_findings, list):
        for item in ranked_findings:
            if not isinstance(item, dict):
                continue
            family = str(item.get("family", "")).strip()
            if family and family != "none found":
                return family

    clues: list[str] = []
    for field_name in ("selected_indicator_phrase", "hidden_indicators", "anomalies", "evidence"):
        value = parsed.get(field_name, "none found")
        if isinstance(value, list):
            clues.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip():
            clues.append(value.strip())
    inferred = _extract_specific_families(clues)
    return inferred[0] if inferred else None


def _collapse_legacy_result_to_detection(parsed: dict) -> dict:
    summary = "Financial or ledger-style tabular data."
    if isinstance(parsed, dict):
        raw_summary = str(parsed.get("summary", "")).strip()
        if raw_summary:
            summary = raw_summary.splitlines()[0].strip() or summary

    presence_value = str(parsed.get("hidden_data_present", "")).strip().lower() if isinstance(parsed, dict) else ""
    family = _detect_family_from_output(parsed if isinstance(parsed, dict) else {})

    if presence_value == "yes":
        hidden_present = True
    elif presence_value == "no":
        hidden_present = False
    else:
        hidden_present = False
        if family:
            hidden_present = True
        elif isinstance(parsed, dict) and _field_has_signal(parsed.get("hidden_data", "none")):
            hidden_present = True
        elif isinstance(parsed, dict):
            clues: list[str] = []
            for field_name in ("hidden_indicators", "anomalies", "evidence"):
                value = parsed.get(field_name, "none found")
                if isinstance(value, list):
                    clues.extend(str(item).strip() for item in value if str(item).strip())
                elif isinstance(value, str) and value.strip():
                    clues.append(value.strip())
            hidden_present = bool(_extract_specific_families(clues))

    if hidden_present and isinstance(parsed, dict) and not _has_concrete_hidden_presence_evidence(parsed, family):
        hidden_present = False

    if hidden_present:
        evidence = _generic_detection_evidence_for_family(family)
        return {
            "summary": "Financial or ledger-style tabular data with evidence of a hidden-data pattern.",
            "hidden_data_present": "yes",
            "evidence": evidence,
        }

    return {
        "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
        "hidden_data_present": "no",
        "evidence": [
            "model did not provide concrete hidden-data evidence",
            "generic suspicion language alone is not treated as a positive",
        ],
    }

def _looks_instructional_or_chatty(output: str) -> bool:
    lowered = output.lower()
    markers = [
        "here is",
        "python",
        "script",
        "solution",
        "let me know",
        "help with anything else",
        "sorted list",
        "```",
        "i can provide",
        "you can",
        "follow-up",
        "follow up",
    ]
    return any(marker in lowered for marker in markers)

def _normalize_model_output(output: str) -> str:
    parsed = _extract_json_payload(output)
    if parsed is None:
        fallback = {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": ["model output was unstructured"],
            "hidden_indicators": ["known-technique check could not be normalized from model output"],
            "hidden_data": "none",
            "evidence": ["model returned off-schema output; see raw_model_output"],
            "raw_model_output": output if output else "",
        }
        return json.dumps(fallback, ensure_ascii=False)

    summary = str(parsed.get("summary", "")).strip()
    if not summary:
        summary = "Financial or ledger-style tabular data."
    else:
        summary = summary.splitlines()[0].strip()
        if len(summary) > 140:
            summary = summary[:137].rstrip() + "..."

    normalized = {
        "summary": summary,
        "anomalies": _normalize_list_field(parsed.get("anomalies"), "none found"),
        "hidden_indicators": _normalize_list_field(parsed.get("hidden_indicators"), "none found"),
        "hidden_data": str(parsed.get("hidden_data", "none")).strip() or "none",
        "evidence": _normalize_list_field(parsed.get("evidence"), "none found"),
    }
    raw_model_output = parsed.get("raw_model_output")
    if raw_model_output not in (None, ""):
        normalized["raw_model_output"] = str(raw_model_output)
    return json.dumps(normalized, ensure_ascii=False)

def _normalize_family_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    if parsed is None:
        parsed = _extract_loose_family_payload(output)
    if parsed is None:
        return {
            "summary": "Financial or ledger-style tabular data.",
            "family_checks": "none found",
            "candidate_families": "none found",
            "evidence": ["family detection returned off-schema output; see raw_model_output"],
            "raw_model_output": output if output else "",
        }

    family_checks_raw = parsed.get("family_checks", [])
    normalized_checks: list[dict] = []
    derived_candidates: list[str] = []
    allowed_names = [item["name"] for item in KNOWN_TECHNIQUE_FAMILIES]
    if isinstance(family_checks_raw, list):
        allowed_name_set = set(allowed_names)
        for item in family_checks_raw:
            if not isinstance(item, dict):
                continue
            family_name = str(item.get("family", "")).strip()
            if not family_name:
                continue
            match_value = str(item.get("match", "uncertain")).strip().lower()
            if match_value not in {"yes", "no", "uncertain"}:
                match_value = "uncertain"
            evidence_value = str(item.get("evidence", "")).strip() or "none found"
            decoded_value = str(item.get("decoded_candidate", "")).strip() or "none"
            normalized_checks.append(
                {
                    "family": family_name,
                    "match": match_value,
                    "evidence": evidence_value,
                    "decoded_candidate": decoded_value,
                }
            )
            if family_name in allowed_name_set and match_value in {"yes", "uncertain"}:
                derived_candidates.append(family_name)

    candidate_families = _normalize_list_field(parsed.get("candidate_families"), "none found")
    if candidate_families == "none found" and derived_candidates:
        candidate_families = _dedupe_items(derived_candidates)

    raw_model_output = str(parsed.get("raw_model_output", "")).strip()
    salvage_text = " ".join(
        part for part in [
            output if output else "",
            raw_model_output,
            json.dumps(parsed, ensure_ascii=False),
        ]
        if part
    )
    salvaged_candidates = [name for name in allowed_names if name in salvage_text]
    if candidate_families == "none found" and salvaged_candidates:
        candidate_families = _dedupe_items(salvaged_candidates)
    elif isinstance(candidate_families, list):
        candidate_families = _dedupe_items(
            [item for item in candidate_families if item in allowed_names] + salvaged_candidates
        ) or "none found"
    elif isinstance(candidate_families, str) and candidate_families not in {"none found", *allowed_names}:
        candidate_families = _dedupe_items(salvaged_candidates) or "none found"

    return {
        "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
        "family_checks": normalized_checks or "none found",
        "candidate_families": candidate_families,
        "evidence": _normalize_list_field(parsed.get("evidence"), "none found"),
        "raw_model_output": raw_model_output,
    }

def _normalize_verification_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    if parsed is None:
        return {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": ["verification output was unstructured"],
            "hidden_indicators": ["verification could not be normalized"],
            "hidden_data": "none",
            "evidence": ["verification returned off-schema output; see raw_model_output"],
            "raw_model_output": output if output else "",
        }
    normalized = {
        "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
        "anomalies": _normalize_list_field(parsed.get("anomalies"), "none found"),
        "hidden_indicators": _normalize_list_field(parsed.get("hidden_indicators"), "none found"),
        "hidden_data": parsed.get("hidden_data", "none"),
        "evidence": _normalize_list_field(parsed.get("evidence"), "none found"),
        "raw_model_output": str(parsed.get("raw_model_output", "")).strip(),
    }
    return normalized

def _normalize_candidate_decision_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    allowed_names = [item["name"] for item in KNOWN_TECHNIQUE_FAMILIES]
    if parsed is None:
        parsed = _extract_loose_candidate_payload(output)

    def _normalize_hidden_data_items(value) -> list[str]:
        if isinstance(value, list):
            return _dedupe_items(
                [
                    str(item).strip()
                    for item in value
                    if str(item).strip() and str(item).strip().lower() != "none"
                ]
            )
        text = str(value or "").strip()
        if not text or text.lower() == "none":
            return []
        return [text]

    def _normalize_ranked_findings(value) -> list[dict]:
        if not isinstance(value, list):
            return []
        ranked: list[dict] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            family = str(item.get("family", "")).strip()
            if family not in allowed_names:
                family = _infer_specific_family(
                    [
                        json.dumps(item, ensure_ascii=False),
                        str(item.get("indicator", "")),
                        str(item.get("evidence", "")),
                        str(item.get("hidden_data", "")),
                    ]
                ) or ""
            if not family:
                continue
            confidence = str(item.get("confidence", "low")).strip().lower() or "low"
            if confidence not in {"high", "medium", "low", "none"}:
                confidence = "low"
            indicator = str(item.get("indicator", "")).strip() or _canonical_indicator_for_family(family)
            evidence_items = _normalize_list_field(item.get("evidence"), "none found")
            if isinstance(evidence_items, str):
                evidence_items = [] if evidence_items == "none found" else [evidence_items]
            ranked.append(
                {
                    "family": family,
                    "confidence": confidence,
                    "indicator": indicator,
                    "hidden_data": _normalize_hidden_data_items(item.get("hidden_data", "none")),
                    "evidence": evidence_items,
                }
            )
        return ranked

    if parsed is None:
        inferred_family = _infer_specific_family([output])
        if inferred_family:
            return {
                "summary": "Financial or ledger-style tabular data.",
                "anomalies": _canonical_anomalies_for_family(inferred_family) or "none found",
                "hidden_indicators": [_canonical_indicator_for_family(inferred_family), f"candidate family flagged: {inferred_family}"],
                "hidden_data": "none",
                "evidence": [f"specific trained-technique clue matched: {inferred_family}"],
                "raw_model_output": output if output else "",
            }
        return json.loads(_normalize_model_output(output))

    ranked_findings = _normalize_ranked_findings(parsed.get("ranked_findings"))
    if not ranked_findings:
        likely_families = parsed.get("likely_families", "none found")
        if isinstance(likely_families, str):
            likely_families = [] if likely_families.strip().lower() in {"", "none", "none found"} else [likely_families.strip()]
        elif isinstance(likely_families, list):
            likely_families = [
                str(item).strip()
                for item in likely_families
                if str(item).strip() and str(item).strip().lower() not in {"none", "none found"}
            ]
        else:
            likely_families = []
        likely_families = _dedupe_items(
            [
                family
                for family in likely_families
                if family in allowed_names
            ],
            limit=2,
        )
        evidence_items = _normalize_list_field(parsed.get("evidence"), "none found")
        if isinstance(evidence_items, str):
            evidence_items = [] if evidence_items == "none found" else [evidence_items]
        hidden_items = _normalize_hidden_data_items(parsed.get("hidden_data", "none"))
        if likely_families:
            ranked_findings = [
                {
                    "family": family,
                    "confidence": "medium",
                    "indicator": _canonical_indicator_for_family(family),
                    "hidden_data": hidden_items if idx == 0 else [],
                    "evidence": evidence_items[:3],
                }
                for idx, family in enumerate(likely_families)
            ]
    if not ranked_findings:
        selected_family = str(parsed.get("selected_family", "")).strip()
        if selected_family not in allowed_names:
            selected_family = _infer_specific_family(
                [
                    json.dumps(parsed, ensure_ascii=False),
                    str(parsed.get("selected_indicator_phrase", "")),
                    str(parsed.get("evidence", "")),
                    output,
                ]
            ) or ""
        selected_indicator = str(parsed.get("selected_indicator_phrase", "")).strip()
        if not selected_indicator and selected_family:
            selected_indicator = _canonical_indicator_for_family(selected_family)
        if selected_family:
            evidence_items = _normalize_list_field(parsed.get("evidence"), "none found")
            if isinstance(evidence_items, str):
                evidence_items = [] if evidence_items == "none found" else [evidence_items]
            ranked_findings = [
                {
                    "family": selected_family,
                    "confidence": str(parsed.get("family_confidence", "low")).strip().lower() or "low",
                    "indicator": selected_indicator,
                    "hidden_data": _normalize_hidden_data_items(parsed.get("hidden_data", "none")),
                    "evidence": evidence_items,
                }
            ]

    if ranked_findings:
        anomalies: list[str] = []
        hidden_indicators: list[str] = []
        hidden_data_values: list[str] = []
        evidence: list[str] = []
        for finding in ranked_findings[:3]:
            anomalies.extend(_canonical_anomalies_for_family(finding["family"]))
            hidden_indicators.append(finding["indicator"] or _canonical_indicator_for_family(finding["family"]))
            hidden_indicators.append(f"candidate family flagged: {finding['family']}")
            hidden_data_values.extend(finding["hidden_data"])
            evidence.extend(finding["evidence"])
        normalized = {
            "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
            "anomalies": _dedupe_items(anomalies) or "none found",
            "hidden_indicators": _dedupe_items(hidden_indicators) or "none found",
            "hidden_data": _dedupe_items(hidden_data_values) if hidden_data_values else "none",
            "evidence": _dedupe_items(evidence) or "none found",
        }
    else:
        evidence = _normalize_list_field(parsed.get("evidence"), "none found")
        hidden_data = str(parsed.get("hidden_data", "none")).strip() or "none"
        anomalies = _normalize_list_field(parsed.get("anomalies"), "none found")
        hidden_indicators = _normalize_list_field(parsed.get("hidden_indicators"), "none found")
        normalized = {
            "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
            "anomalies": anomalies or "none found",
            "hidden_indicators": hidden_indicators or "none found",
            "hidden_data": hidden_data,
            "evidence": evidence,
        }
    raw_model_output = parsed.get("raw_model_output")
    if raw_model_output not in (None, ""):
        normalized["raw_model_output"] = str(raw_model_output)
    return normalized


def _normalize_detection_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    if isinstance(parsed, dict):
        return _collapse_legacy_result_to_detection(parsed)
    return _collapse_legacy_result_to_detection({"summary": "", "evidence": [output] if output else []})


def _repair_detection_output(raw_output: str, context_block: str, candidate_block: str, extra_guidance: str = "") -> dict:
    app.logger.warning(
        "Detection output was off-schema; attempting schema conversion. raw_preview=%r",
        (raw_output or "")[:500],
    )
    prompt = (
        "You are converting a prior analyst response into strict JSON. "
        "Do not add new analysis, code, scripts, explanations, or follow-up text. "
        "Use only the supplied file context, candidate evidence, and prior analyst response. "
        "Return STRICT JSON ONLY with keys: summary, hidden_data_present, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "hidden_data_present must be exactly yes or no. "
        "evidence must be an array of 1 to 2 short generic findings and must not reveal or reconstruct any hidden payload. "
        "Prefer no over guessing when the evidence is weak or conflicting. "
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nCANDIDATE EVIDENCE\n{candidate_block}\n"
        f"\nPRIOR ANALYST RESPONSE\n{raw_output}\n"
    )
    repaired_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
    return _normalize_detection_result(repaired_output)

def _repair_family_detection_output(raw_output: str, context_block: str, extra_guidance: str = "") -> dict:
    app.logger.warning(
        "Family detection output was off-schema; attempting schema conversion. raw_preview=%r",
        (raw_output or "")[:500],
    )
    prompt = (
        "You are converting a prior analyst response into strict JSON. "
        "Do not add new analysis, code, scripts, explanations, or follow-up text. "
        "Use only the supplied file context and the prior analyst response. "
        "Return STRICT JSON ONLY with keys: summary, family_checks, candidate_families, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "family_checks must be an array with one object per trained family using exactly these keys: family, match, evidence, decoded_candidate. "
        "For each family, match must be yes, no, or uncertain. "
        "candidate_families must be an array of only the family names marked yes or uncertain, or the single string \"none found\". "
        "If the prior response mentions a hiding-technique family in narrative form, convert it into the correct family_checks entry instead of discarding it. "
        "If the prior response contains code or instructions, ignore the code and extract only the underlying hidden-data claim, if any. "
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nPRIOR ANALYST RESPONSE\n{raw_output}\n"
    )
    repaired_output = _run_ollama_raw(prompt, timeout=OLLAMA_FAMILY_TIMEOUT)
    return _normalize_family_result(repaired_output)

def _repair_verification_output(raw_output: str, context_block: str, candidate_families: list[str], extra_guidance: str = "") -> dict:
    app.logger.warning(
        "Verification output was off-schema; attempting schema conversion. raw_preview=%r",
        (raw_output or "")[:500],
    )
    prompt = (
        "You are converting a prior analyst response into strict JSON. "
        "Do not add new analysis, code, scripts, explanations, or follow-up text. "
        "Use only the supplied file context, the candidate families, and the prior analyst response. "
        "This is not a fresh analysis pass; it is only a schema-conversion and confirmation step. "
        "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
        "hidden_data must be decoded hidden content if present, otherwise \"none\". "
        "If the prior response contains code or instructions, ignore the code and extract only the underlying hidden-data claim, if any. "
        f"Candidate families to verify: {', '.join(candidate_families) if candidate_families else 'none'}. "
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nPRIOR ANALYST RESPONSE\n{raw_output}\n"
    )
    repaired_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
    return _normalize_verification_result(repaired_output)

def _repair_candidate_review_output(raw_output: str, context_block: str, candidate_block: str, extra_guidance: str = "") -> dict:
    app.logger.warning(
        "Candidate review output was off-schema; attempting schema conversion. raw_preview=%r",
        (raw_output or "")[:500],
    )
    prompt = (
        "You are converting a prior analyst response into strict JSON. "
        "Do not add new analysis, code, scripts, explanations, or follow-up text. "
        "Use only the supplied file context, the candidate evidence, and the prior analyst response. "
        "Return STRICT JSON ONLY with keys: summary, ranked_findings, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "ranked_findings must be an array of up to 3 objects with keys family, confidence, indicator, hidden_data, evidence. "
        "Each family must be one allowed family name or \"none found\". "
        "hidden_data must be the most human-readable hidden content if present, otherwise \"none\". "
        "evidence must be an array of 1 to 3 short strings or the single string \"none found\". "
        "Keep initials-only, repeated-digit, or parity-only clues as weak unless the candidate evidence includes a readable decode or a clean date/coordinate conversion. "
        "If the prior response contains code or instructions, ignore the code and extract only the underlying hidden-data claim, if any. "
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nCANDIDATE EVIDENCE\n{candidate_block}\n"
        f"\nPRIOR ANALYST RESPONSE\n{raw_output}\n"
    )
    repaired_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
    return _normalize_candidate_decision_result(repaired_output)

def _run_ollama_raw(prompt: str, timeout: int | None = None, model: str | None = None) -> str:
    model_name = model or OLLAMA_MODEL
    app.logger.info("Running ollama model=%s prompt_bytes=%s", model_name, len(prompt.encode("utf-8", errors="replace")))
    cmd = [
        "docker",
        "exec",
        "-e",
        "TERM=dumb",
        "-e",
        "NO_COLOR=1",
        "-i",
        OLLAMA_CONTAINER,
        "ollama",
        "run",
        model_name,
    ]
    result = subprocess.run(
        cmd,
        input=prompt.encode("utf-8", errors="replace"),
        capture_output=True,
        timeout=timeout or OLLAMA_TIMEOUT,
        check=False,
    )
    stdout_text = result.stdout.decode("utf-8", errors="replace").strip()
    stdout_error_text = _clean_runtime_message(stdout_text)
    stderr_text = _clean_runtime_message(result.stderr.decode("utf-8", errors="replace"))
    if result.returncode != 0:
        error_text = next(
            (
                candidate
                for candidate in (stderr_text, stdout_error_text)
                if _has_meaningful_runtime_text(candidate)
            ),
            "",
        )
        if not error_text:
            error_text = stderr_text or stdout_error_text
        raise RuntimeError(error_text or f"ollama run failed with code {result.returncode}")
    app.logger.info("ollama run complete model=%s bytes_out=%s", model_name, len(result.stdout))
    return stdout_text

def run_ollama_prompt(prompt: str, timeout: int | None = None) -> str:
    output = _run_ollama_raw(prompt, timeout=timeout)
    return _normalize_model_output(output)

PROMPT_CONTRACT = (
    "Analyze the file directly using only the supplied file context. "
    "Start with hiding techniques similar to the trained examples, then broaden to other anomalies if needed. "
    "Prefer decodable encodings before structural anomalies. "
    "Perform the reasoning internally and report findings directly. "
    "Do not ask for follow-up. Do not suggest commands, scripts, SQL, Python, pseudocode, or methods for the user to run. "
    "Treat the file as tabular or byte evidence unless the supplied views explicitly contain executable code. "
    "Do not reinterpret ordinary ledger rows, IDs, dates, or values as source code. "
    "If the supplied views do not explicitly show code, do not mention Python, SQL, or scripts. "
    "Do not summarize business topics, categories, or trends unless they are directly relevant to hidden-data evidence. "
    "Focus on hidden content, suspicious patterns, and evidence that supports or weakens a hidden-data hypothesis. "
)

def _run_family_detection_pass(context_block: str, extra_guidance: str = "") -> tuple[dict, list[str]]:
    issues: list[str] = []
    app.logger.info("Running trained-family detection pass")
    family_names = ", ".join(item["name"] for item in KNOWN_TECHNIQUE_FAMILIES)
    family_hints = " ".join(f"{item['name']}: {item['hint']}" for item in KNOWN_TECHNIQUE_FAMILIES)
    prompt = (
        "You are analyzing ONE file. The metadata, head/tail bytes, parsed CSV views, candidate decodings, and extracted strings are views of the SAME file. "
        + PROMPT_CONTRACT +
        "Start with the trained hiding-technique families and do not give generic help or instructions. "
        f"Technique families to consider: {family_names}. "
        f"Family hints: {family_hints} "
        f"Additional analyst guidance: {extra_guidance or 'none'}. "
        "You must evaluate EVERY trained family explicitly and do not skip any family. "
        "Use these evidence sources in order: metadata_comment_lines, candidate_decodings, numeric_last_digits_by_column, text_initials_by_column, parsed_rows_head, parsed_rows_tail, extracted strings. "
        "Search first for decodable encodings, then for structural or cross-row anomalies. "
        "Return STRICT JSON ONLY with keys: summary, family_checks, candidate_families, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "family_checks must be an array with one object per trained family using exactly these keys: family, match, evidence, decoded_candidate. "
        "For each family, match must be yes, no, or uncertain. evidence must be one short line grounded in the supplied views. decoded_candidate must be decoded hidden content if present, otherwise \"none\". "
        "candidate_families must be an array of only the family names marked yes or uncertain, or the single string \"none found\". "
        "evidence must be an array of the strongest cross-family findings or the single string \"none found\"."
        + context_block
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_FAMILY_TIMEOUT)
        normalized = _normalize_family_result(raw_output)
        if normalized.get("family_checks") == "none found" and raw_output.strip():
            repaired = _repair_family_detection_output(
                raw_output,
                context_block,
                extra_guidance=extra_guidance,
            )
            if repaired.get("family_checks") != "none found":
                issues.append("family detection required schema conversion")
                normalized = repaired
            else:
                issues.append("family detection schema conversion produced no family checks")
    except subprocess.TimeoutExpired:
        app.logger.warning("Family detection pass timed out after %ss", OLLAMA_FAMILY_TIMEOUT)
        issues.append("family detection pass timed out")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "candidate_families": "none found",
            "evidence": "none found",
        }
    except Exception as exc:
        app.logger.warning("Family detection pass failed: %s", exc)
        issues.append(f"family detection pass failed: {exc}")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "candidate_families": "none found",
            "evidence": "none found",
        }
    return normalized, issues

def _run_family_verification_pass(
    context_block: str,
    candidate_families: list[str],
    extra_guidance: str = "",
) -> tuple[dict, list[str]]:
    issues: list[str] = []
    app.logger.info("Running trained-family verification pass for %s candidate families", len(candidate_families))
    prompt = (
        "You are analyzing ONE file. The metadata, head/tail bytes, parsed CSV views, candidate decodings, and extracted strings are views of the SAME file. "
        + PROMPT_CONTRACT +
        "This is NOT a fresh analysis pass. Verify only the candidate trained hiding-technique families that were already flagged. "
        "Do not describe the dataset generally, do not explain methods, and do not produce code-like text. "
        "Confirm or reject the flagged families using the supplied evidence only. "
        f"Candidate families to verify: {', '.join(candidate_families) if candidate_families else 'none'}. "
        f"Additional analyst guidance: {extra_guidance or 'none'}. "
        "For any family that truly matches, extract hidden content if possible and describe the strongest supporting evidence. "
        "If no family is confirmed, report none found rather than giving a general description of the file. "
        "Never mention Python, SQL, classes, methods, scripts, portfolios, or stocks unless those exact terms appear in the supplied file context. "
        "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
        "hidden_data must be decoded hidden content if found, otherwise \"none\"."
        + context_block
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
        normalized = _normalize_verification_result(raw_output)
        verification_off_schema = (
            normalized.get("anomalies") == ["verification output was unstructured"]
            or normalized.get("hidden_indicators") == ["verification could not be normalized"]
        )
        if verification_off_schema and raw_output.strip():
            repaired = _repair_verification_output(
                raw_output,
                context_block,
                candidate_families,
                extra_guidance=extra_guidance,
            )
            repaired_off_schema = (
                repaired.get("anomalies") == ["verification output was unstructured"]
                or repaired.get("hidden_indicators") == ["verification could not be normalized"]
            )
            if not repaired_off_schema:
                issues.append("family verification required schema conversion")
                normalized = repaired
            else:
                issues.append("family verification schema conversion remained off-schema")
    except subprocess.TimeoutExpired:
        app.logger.warning("Family verification pass timed out after %ss", OLLAMA_VERIFY_TIMEOUT)
        issues.append("family verification pass timed out")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": ["family verification pass timed out"],
        }
    except Exception as exc:
        app.logger.warning("Family verification pass failed: %s", exc)
        issues.append(f"family verification pass failed: {exc}")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": [f"family verification pass failed: {exc}"],
        }
    return normalized, issues

def _run_broad_anomaly_pass(
    context_block: str,
    verified_findings: dict,
    analysis_issues: list[str],
    extra_guidance: str = "",
) -> dict:
    app.logger.info("Running broad anomaly pass after trained-family analysis with %s issues", len(analysis_issues))
    known_summary = str(verified_findings.get("hidden_data", "none"))
    issue_summary = "; ".join(analysis_issues) if analysis_issues else "none"
    prompt = (
        "You are analyzing ONE file. The metadata, head/tail bytes, parsed CSV views, candidate decodings, and extracted strings are views of the SAME file. "
        + PROMPT_CONTRACT +
        "A trained-family detection and verification pass has already been run. Look only for additional anomalies not already captured there. "
        f"Known trained-family findings already captured: {known_summary}. "
        f"Earlier analysis issues: {issue_summary}. "
        f"Additional analyst guidance: {extra_guidance or 'none'}. "
        "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type with no specifics. "
        "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
        "hidden_data must be decoded hidden content if additional content is found, otherwise \"none\"."
        + context_block
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_BROAD_TIMEOUT)
        normalized_output = _normalize_model_output(raw_output)
        return json.loads(normalized_output)
    except subprocess.TimeoutExpired:
        app.logger.warning("Broad anomaly pass timed out after %ss", OLLAMA_BROAD_TIMEOUT)
        return {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": ["broad anomaly pass timed out"],
        }
    except Exception as exc:
        app.logger.warning("Broad anomaly pass failed: %s", exc)
        return {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": [f"broad anomaly pass failed: {exc}"],
        }

def _run_candidate_review_pass(
    context_block: str,
    candidate_block: str,
    extra_guidance: str = "",
) -> tuple[dict, list[str]]:
    issues: list[str] = []
    app.logger.info("Running candidate review pass")
    prompt = (
        "You are analyzing ONE file. The compact file context and candidate evidence are views of the SAME file. "
        + PROMPT_CONTRACT +
        "All candidate evidence was extracted from the entire file before this step and already pruned by deterministic validators. Review every family summary and ranked candidate before deciding. "
        "Do not stop at the first suspicious pattern. Rank the strongest findings after considering all supplied evidence. "
        "Use the candidate evidence as your primary basis for judgment. "
        "Treat initials-only strings as weak unless they form clearly human-readable text. "
        "Treat raw digit sequences, repeated digits, parity hints, or short decodes without a printable readable result as weak evidence. "
        "Treat timestamp/date families as strong only when a value converts cleanly to a plausible calendar date. "
        "Treat coordinate families as strong only when a pair is a valid latitude/longitude pair. "
        "Treat phone-style numeric fields as strong only when they validate cleanly as a phone-number pattern. "
        "If the available evidence is weak or conflicting, prefer none found over guessing. "
        "Do not generate code or methods. Do not explain how to detect the pattern. "
        f"Allowed family names: {', '.join(item['name'] for item in KNOWN_TECHNIQUE_FAMILIES)}. "
        "Return only the strongest plausible findings. Prefer decoded content that is most human-readable or most readily convertible to human-readable text. "
        "Return STRICT JSON ONLY with keys: summary, ranked_findings, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "ranked_findings must be an array of up to 3 objects with keys family, confidence, indicator, hidden_data, evidence. "
        "family must be one allowed family name or \"none found\". confidence must be high, medium, low, or none. "
        "indicator must be a short phrase grounded in the evidence. hidden_data must be the best decoded candidate for that finding or \"none\". "
        "At the top level, hidden_data must list the best 1 to 3 most human-readable payloads across all findings or \"none\". "
        "evidence must be an array of 1 to 3 short strings. Keep the entire response extremely short."
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nCANDIDATE EVIDENCE\n{candidate_block}\n"
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
        normalized = _normalize_candidate_decision_result(raw_output)
        candidate_review_off_schema = (
            normalized.get("anomalies") == ["model output was unstructured"]
            or normalized.get("hidden_indicators") == ["known-technique check could not be normalized from model output"]
        )
        if candidate_review_off_schema and raw_output.strip():
            repaired = _repair_candidate_review_output(
                raw_output,
                context_block,
                candidate_block,
                extra_guidance=extra_guidance,
            )
            repaired_off_schema = (
                repaired.get("anomalies") == ["model output was unstructured"]
                or repaired.get("hidden_indicators") == ["known-technique check could not be normalized from model output"]
            )
            if not repaired_off_schema:
                issues.append("candidate review required schema conversion")
                normalized = repaired
            else:
                issues.append("candidate review schema conversion remained off-schema")
    except subprocess.TimeoutExpired:
        app.logger.warning("Candidate review pass timed out after %ss", OLLAMA_VERIFY_TIMEOUT)
        issues.append("candidate review pass timed out")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": ["candidate review pass timed out"],
        }
    except Exception as exc:
        app.logger.warning("Candidate review pass failed: %s", exc)
        issues.append(f"candidate review pass failed: {exc}")
        normalized = {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": "none found",
            "hidden_indicators": "none found",
            "hidden_data": "none",
            "evidence": [f"candidate review pass failed: {exc}"],
        }
    return normalized, issues


def _run_hidden_presence_pass(
    context_block: str,
    candidate_block: str,
    extra_guidance: str = "",
) -> tuple[dict, list[str]]:
    issues: list[str] = []
    app.logger.info("Running hidden-presence detection pass")
    prompt = (
        "You are analyzing ONE file. The compact file context and candidate evidence are views of the SAME file. "
        "Decide only whether intentionally hidden data appears to be present. "
        "Do not decode, reconstruct, quote, or reveal any hidden payload. "
        "Do not return family names, ranked findings, code, scripts, or follow-up advice. "
        "Use the candidate evidence as your primary basis for judgment. "
        "Only answer yes when deliberate hidden signaling is stronger than ordinary business-data variation, noise, or formatting quirks. "
        "If you answer yes, at least one evidence item must include a specific anchor such as a row number, column name, field name, cell reference, or quoted value clue. "
        "If the evidence is weak, conflicting, or ordinary, answer no. "
        "Return STRICT JSON ONLY with keys: summary, hidden_data_present, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "hidden_data_present must be exactly yes or no. "
        "evidence must be an array of 1 to 2 short findings and must not reveal any hidden payload. "
        f"Additional analyst guidance: {extra_guidance or 'none'}."
        f"{context_block}\n"
        f"\nCANDIDATE EVIDENCE\n{candidate_block}\n"
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
        normalized = _normalize_detection_result(raw_output)
        if not isinstance(_extract_json_payload(raw_output), dict):
            repaired = _repair_detection_output(
                raw_output,
                context_block,
                candidate_block,
                extra_guidance=extra_guidance,
            )
            normalized = repaired
            issues.append("hidden-presence detection required schema conversion")
    except subprocess.TimeoutExpired:
        app.logger.warning("Hidden-presence detection pass timed out after %ss", OLLAMA_VERIFY_TIMEOUT)
        issues.append("hidden-presence detection pass timed out")
        normalized = {
            "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
            "hidden_data_present": "no",
            "evidence": ["hidden-presence detection pass timed out"],
        }
    except Exception as exc:
        app.logger.warning("Hidden-presence detection pass failed: %s", exc)
        if OLLAMA_FALLBACK_MODEL and OLLAMA_FALLBACK_MODEL != OLLAMA_MODEL and _is_ollama_runner_failure(str(exc)):
            fallback_model = OLLAMA_FALLBACK_MODEL
            app.logger.warning(
                "Primary hidden-presence model %s failed; retrying fallback %s",
                OLLAMA_MODEL,
                fallback_model,
            )
            issues.append(f"primary detection model unavailable; retried with {fallback_model}")
            try:
                raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT, model=fallback_model)
                normalized = _normalize_detection_result(raw_output)
                if not isinstance(_extract_json_payload(raw_output), dict):
                    repaired = _repair_detection_output(
                        raw_output,
                        context_block,
                        candidate_block,
                        extra_guidance=extra_guidance,
                    )
                    normalized = repaired
                    issues.append("fallback detection required schema conversion")
                normalized["_model_used"] = fallback_model
            except subprocess.TimeoutExpired:
                app.logger.warning("Fallback hidden-presence detection pass timed out after %ss", OLLAMA_VERIFY_TIMEOUT)
                issues.append(f"fallback detection model timed out: {fallback_model}")
                normalized = {
                    "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
                    "hidden_data_present": "no",
                    "evidence": ["fallback detection model timed out"],
                    "_model_used": fallback_model,
                }
            except Exception as fallback_exc:
                app.logger.warning("Fallback hidden-presence detection pass failed: %s", fallback_exc)
                issues.append(f"fallback detection model unavailable: {fallback_model}")
                normalized = {
                    "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
                    "hidden_data_present": "no",
                    "evidence": ["all detection models unavailable"],
                    "_model_used": fallback_model,
                }
        else:
            issues.append("hidden-presence detection pass failed")
            normalized = {
                "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
                "hidden_data_present": "no",
                "evidence": ["hidden-presence detection pass failed"],
            }
    return normalized, issues

def analyze_with_known_techniques(context: dict, extra_guidance: str = "") -> str:
    compact_context_block = (
        f"\n\nFILE CONTEXT\n"
        f"Filename: {context['filename']}\n"
        f"Column names: {json.dumps(context['column_names'], ensure_ascii=False)}\n"
        f"Parsed CSV head rows: {json.dumps(context['parsed_rows_head'][:2], ensure_ascii=False)}\n"
        f"Numeric last-digit views by column: {json.dumps(context['numeric_last_digits_by_column'], ensure_ascii=False)}\n"
        f"Text initials by column: {json.dumps(context['text_initials_by_column'], ensure_ascii=False)}\n"
        f"Candidate decodings from fields/strings: {json.dumps(context['candidate_decodings'][:2], ensure_ascii=False)}\n"
    )
    all_candidate_views = _build_candidate_views(context)
    review_candidate_views = _prune_candidates_for_review(all_candidate_views)
    deterministic_result = _deterministic_candidate_decision(context, review_candidate_views)
    if deterministic_result is not None:
        detection_result = _collapse_legacy_result_to_detection(deterministic_result)
        return json.dumps(detection_result, ensure_ascii=False)

    candidate_review_payload = _build_ranked_candidate_review_payload(review_candidate_views, max_families=6, max_items_per_family=3)
    candidate_block = json.dumps(candidate_review_payload, ensure_ascii=False)
    detection_result, detection_issues = _run_hidden_presence_pass(
        compact_context_block,
        candidate_block,
        extra_guidance=extra_guidance,
    )
    if detection_issues:
        detection_result["evidence"] = _dedupe_items(
            list(detection_result.get("evidence", [])) + detection_issues,
            limit=3,
        )
    return json.dumps(detection_result, ensure_ascii=False)

def _set_job(job_id: str, **updates) -> None:
    with _jobs_lock:
        entry = _jobs.get(job_id, {})
        entry.update(updates)
        _jobs[job_id] = entry


def _build_analysis_payload(filename: str, output: str) -> dict:
    try:
        analysis_result = json.loads(output)
    except Exception:
        analysis_result = {
            "summary": "Financial or ledger-style tabular data with no clear hidden-data pattern.",
            "hidden_data_present": "no",
            "evidence": ["analysis output could not be parsed"],
        }
    model_used = analysis_result.pop("_model_used", OLLAMA_MODEL) if isinstance(analysis_result, dict) else OLLAMA_MODEL
    return {
        "status": "Analysis complete",
        "filename": filename,
        "analysis_mode": "hidden_presence_only",
        "llama_model": model_used,
        "analysis_result": analysis_result,
        "llama_output": output,
        "detection_evidence_mode": DETECTION_EVIDENCE_MODE,
        "server_code_version": CODE_VERSION,
        "server_code_source": CODE_SOURCE,
    }

def _run_job(job_id: str, dest: Path, prompt: str, filename: str) -> None:
    _set_job(job_id, status="running", started_at=time.time())
    try:
        context = build_file_context(dest)
        output = analyze_with_known_techniques(context, extra_guidance=prompt or "")
        _set_job(
            job_id,
            status="done",
            finished_at=time.time(),
            result=_build_analysis_payload(filename, output),
        )
    except Exception as exc:
        app.logger.exception("Ollama execution failed")
        _set_job(
            job_id,
            status="error",
            finished_at=time.time(),
            error=str(exc),
            result={
                "status": "Analysis failed",
                "filename": filename,
                "analysis_mode": "hidden_presence_only",
                "llama_model": OLLAMA_MODEL,
                "llama_error": str(exc),
            },
        )

def _enqueue_job(dest: Path, prompt: str, filename: str) -> str:
    job_id = uuid.uuid4().hex
    _set_job(job_id, status="queued", created_at=time.time())
    thread = threading.Thread(target=_run_job, args=(job_id, dest, prompt, filename), daemon=True)
    thread.start()
    return job_id

@app.route("/scan", methods=["POST"])
def scan():
    remote_addr = request.remote_addr
    header_keys = sorted(request.headers.keys())
    app.logger.info("Incoming /scan from %s; headers: %s", remote_addr, header_keys)
    is_remote = bool(request.headers.get("Cf-Connecting-Ip"))

    filename = request.headers.get("X-Filename")
    if not filename:
        filename = request.args.get("filename")
    app.logger.info("X-Filename header=%r; query filename=%r", request.headers.get("X-Filename"), request.args.get("filename"))
    if not filename:
        return "Missing filename header", 400

    dest = UPLOAD_DIR / filename
    chunk_size = 256 * 1024
    content_length = request.content_length

    with open(dest, "wb") as f:
        if content_length is not None:
            remaining = content_length
            while remaining > 0:
                chunk = request.stream.read(min(chunk_size, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        else:
            while True:
                chunk = request.stream.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)

    prompt = request.headers.get("X-Prompt") or request.args.get("prompt")
    if is_remote:
        job_id = _enqueue_job(dest, prompt, filename)
        return jsonify({
            "status": "queued",
            "job_id": job_id,
            "status_url": f"/scan/{job_id}",
        }), 202
    try:
        context = build_file_context(dest)
        output = analyze_with_known_techniques(context, extra_guidance=prompt or "")
        return jsonify(_build_analysis_payload(filename, output)), 200
    except Exception as exc:
        app.logger.exception("Ollama execution failed")
        return jsonify({
            "status": "Analysis failed",
            "filename": filename,
            "analysis_mode": "hidden_presence_only",
            "llama_model": OLLAMA_MODEL,
            "llama_error": str(exc),
        }), 502

    return "File received", 200

@app.route("/scan/<job_id>", methods=["GET"])
def scan_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        resp = jsonify({"status": "not_found", "job_id": job_id})
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp, 404
    status = job.get("status", "queued")
    payload = {
        "status": status,
        "job_id": job_id,
    }
    if status == "done":
        payload["result"] = job.get("result")
    elif status == "error":
        payload["error"] = job.get("error")
        payload["result"] = job.get("result")
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp, 200


if __name__ == "__main__":
    print("Starting server...")
    app.logger.info("Server starting version=%s source=%s", CODE_VERSION, CODE_SOURCE)
    # serve(app, host="0.0.0.0", port=65432, channel_timeout=1000000, asyncore_loop_timeout=5, connection_limit=1000)
    app.run(host="0.0.0.0", port=65432)
