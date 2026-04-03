from flask import Flask, request, jsonify
from pathlib import Path
from waitress import serve
import json
import logging
import os
import subprocess
import hashlib
import mimetypes
import re
import threading
import time
import uuid

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 800 * 1024 * 1024 * 1024
app.logger.setLevel(logging.INFO)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

OLLAMA_CONTAINER = os.environ.get("OLLAMA_CONTAINER", "ollama-server")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "privscan-8b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "3600"))
OLLAMA_PREWARM_TIMEOUT = int(os.environ.get("OLLAMA_PREWARM_TIMEOUT", "120"))
OLLAMA_PREWARM_MESSAGE = os.environ.get("OLLAMA_PREWARM_MESSAGE", "ok")
PREWARM_EACH_REQUEST = os.environ.get("PREWARM_EACH_REQUEST", "false").lower() == "true"
PREWARM_ON_STARTUP = os.environ.get("PREWARM_ON_STARTUP", "true").lower() == "true"
PREWARM_MIN_INTERVAL = int(os.environ.get("PREWARM_MIN_INTERVAL", "300"))
CONTEXT_MAX_BYTES = int(os.environ.get("CONTEXT_MAX_BYTES", "16384"))
CONTEXT_TAIL_BYTES = int(os.environ.get("CONTEXT_TAIL_BYTES", "4096"))
STRINGS_MIN_LEN = int(os.environ.get("STRINGS_MIN_LEN", "4"))
STRINGS_MAX_COUNT = int(os.environ.get("STRINGS_MAX_COUNT", "200"))
STRINGS_MAX_LEN = int(os.environ.get("STRINGS_MAX_LEN", "200"))
TEXT_EXCERPT_CHARS = int(os.environ.get("TEXT_EXCERPT_CHARS", "0"))
STRINGS_SCAN_CHUNK = int(os.environ.get("STRINGS_SCAN_CHUNK", "1048576"))
STRINGS_CARRY_BYTES = int(os.environ.get("STRINGS_CARRY_BYTES", "4096"))
OLLAMA_FAMILY_TIMEOUT = int(os.environ.get("OLLAMA_FAMILY_TIMEOUT", "240"))
OLLAMA_VERIFY_TIMEOUT = int(os.environ.get("OLLAMA_VERIFY_TIMEOUT", "240"))
OLLAMA_BROAD_TIMEOUT = int(os.environ.get("OLLAMA_BROAD_TIMEOUT", "240"))

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

_prewarm_lock = threading.Lock()
_last_prewarm_ts = 0.0
_prewarm_inflight = False
_jobs_lock = threading.Lock()
_jobs: dict[str, dict] = {}

def _prewarm_ollama() -> None:
    global _last_prewarm_ts, _prewarm_inflight
    try:
        cmd = [
            "docker",
            "exec",
            "-i",
            OLLAMA_CONTAINER,
            "ollama",
            "run",
            OLLAMA_MODEL,
        ]
        subprocess.run(
            cmd,
            input=OLLAMA_PREWARM_MESSAGE.encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=OLLAMA_PREWARM_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        app.logger.warning("Prewarm timed out after %ss", OLLAMA_PREWARM_TIMEOUT)
    except Exception:
        app.logger.exception("Prewarm failed")
    finally:
        with _prewarm_lock:
            _last_prewarm_ts = time.time()
            _prewarm_inflight = False

def _maybe_prewarm_async() -> None:
    global _prewarm_inflight
    now = time.time()
    with _prewarm_lock:
        if _prewarm_inflight:
            return
        if now - _last_prewarm_ts < PREWARM_MIN_INTERVAL:
            return
        _prewarm_inflight = True
    thread = threading.Thread(target=_prewarm_ollama, daemon=True)
    thread.start()

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

    return {
        "filename": path.name,
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "mime_guess": mime or "unknown",
        "bytecode_head_hex": _hex_preview(head, CONTEXT_MAX_BYTES),
        "bytecode_tail_hex": _hex_preview(tail, CONTEXT_TAIL_BYTES) if tail else "",
        "strings_full": _extract_strings_stream(path),
        "text_excerpt": text_excerpt,
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
            "evidence": [output[:300]] if output else "none found",
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
    return json.dumps(normalized, ensure_ascii=False)

def _normalize_family_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    if parsed is None:
        return {
            "summary": "Financial or ledger-style tabular data.",
            "candidate_families": "none found",
            "evidence": [output[:300]] if output else ["empty family detection response"],
        }

    return {
        "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
        "candidate_families": _normalize_list_field(parsed.get("candidate_families"), "none found"),
        "evidence": _normalize_list_field(parsed.get("evidence"), "none found"),
    }

def _normalize_verification_result(output: str) -> dict:
    parsed = _extract_json_payload(output)
    if parsed is None:
        return {
            "summary": "Financial or ledger-style tabular data.",
            "anomalies": ["verification output was unstructured"],
            "hidden_indicators": ["verification could not be normalized"],
            "hidden_data": "none",
            "evidence": [output[:300]] if output else ["empty verification response"],
        }
    normalized = {
        "summary": str(parsed.get("summary", "Financial or ledger-style tabular data.")).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
        "anomalies": _normalize_list_field(parsed.get("anomalies"), "none found"),
        "hidden_indicators": _normalize_list_field(parsed.get("hidden_indicators"), "none found"),
        "hidden_data": parsed.get("hidden_data", "none"),
        "evidence": _normalize_list_field(parsed.get("evidence"), "none found"),
    }
    return normalized

def _run_ollama_raw(prompt: str, timeout: int | None = None) -> str:
    app.logger.info("Running ollama model=%s prompt_bytes=%s", OLLAMA_MODEL, len(prompt.encode("utf-8", errors="replace")))
    cmd = [
        "docker",
        "exec",
        "-i",
        OLLAMA_CONTAINER,
        "ollama",
        "run",
        OLLAMA_MODEL,
    ]
    result = subprocess.run(
        cmd,
        input=prompt.encode("utf-8", errors="replace"),
        capture_output=True,
        timeout=timeout or OLLAMA_TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        stderr_text = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(stderr_text or f"ollama run failed with code {result.returncode}")
    app.logger.info("ollama run complete model=%s bytes_out=%s", OLLAMA_MODEL, len(result.stdout))
    return result.stdout.decode("utf-8", errors="replace").strip()

def run_ollama_prompt(prompt: str, timeout: int | None = None) -> str:
    output = _run_ollama_raw(prompt, timeout=timeout)
    return _normalize_model_output(output)

PROMPT_CONTRACT = (
    "You are a forensic CSV analyst, not a coding assistant. "
    "You must do the analysis yourself using only the supplied file context. "
    "Forbidden output: code, pseudocode, commands, scripts, suggestions, follow-up questions, offers of help, "
    "summaries outside the summary field, or restating ordinary rows, columns, IDs, dates, companies, or sample values "
    "unless they are anomaly evidence. "
    "Do not tell the user how to analyze the file. Do not ask the user to run anything. "
    "Do not produce explanatory prose. Any text outside the JSON object is invalid. "
    "If you are about to produce code, a script, instructions, a sorted list, or a narrative explanation, stop and instead "
    "return strict JSON using the required schema. "
    "Check for hiding techniques similar to the trained examples first, then broader anomalies. "
    "Try decodable encodings before structural anomalies. "
    "Do not describe normal structure as evidence. Evidence must point only to hidden-pattern candidates or confirmed anomalies. "
)

def _run_family_detection_pass(context_block: str, extra_guidance: str = "") -> tuple[dict, list[str]]:
    issues: list[str] = []
    app.logger.info("Running trained-family detection pass")
    family_names = ", ".join(item["name"] for item in KNOWN_TECHNIQUE_FAMILIES)
    family_hints = " ".join(f"{item['name']}: {item['hint']}" for item in KNOWN_TECHNIQUE_FAMILIES)
    prompt = (
        "You are analyzing ONE file. The metadata, head/tail bytes, and extracted strings are views of the SAME file. "
        + PROMPT_CONTRACT +
        "Start with the trained hiding-technique families and do not give generic help or instructions. "
        f"Technique families to consider: {family_names}. "
        f"Family hints: {family_hints} "
        f"Additional analyst guidance: {extra_guidance or 'none'}. "
        "First decide which of these families are plausible matches for this file. "
        "Search first for decodable encodings, then for structural or cross-row anomalies. "
        "Return STRICT JSON ONLY with keys: summary, candidate_families, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "candidate_families must be an array of the most plausible family names or the single string \"none found\". "
        "evidence must be an array of short strings or the single string \"none found\"."
        + context_block
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_FAMILY_TIMEOUT)
        normalized = _normalize_family_result(raw_output)
        if _looks_instructional_or_chatty(raw_output) or normalized["candidate_families"] == "none found" and normalized["evidence"] != "none found":
            repair_prompt = (
                "Your previous answer was invalid because it included assistant-style prose, code, or list output instead of strict JSON. "
                + PROMPT_CONTRACT +
                "Do not summarize IDs, do not write code, and do not offer help. "
                "Return STRICT JSON ONLY with keys: summary, candidate_families, evidence. "
                "summary must be 3 to 8 words naming only the general document type. "
                "candidate_families must be an array chosen only from the trained-family names already provided, or the single string \"none found\". "
                "evidence must be an array of short strings or the single string \"none found\". "
                "Previous invalid answer: "
                + raw_output[:1200]
                + context_block
            )
            normalized = _normalize_family_result(
                _run_ollama_raw(repair_prompt, timeout=OLLAMA_FAMILY_TIMEOUT)
            )
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
        "You are analyzing ONE file. The metadata, head/tail bytes, and extracted strings are views of the SAME file. "
        + PROMPT_CONTRACT +
        "Verify only the candidate trained hiding-technique families that were already flagged. "
        f"Candidate families to verify: {', '.join(candidate_families) if candidate_families else 'none'}. "
        f"Additional analyst guidance: {extra_guidance or 'none'}. "
        "For any family that truly matches, extract hidden content if possible and describe the strongest supporting evidence. "
        "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
        "summary must be 3 to 8 words and describe only the general document type. "
        "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
        "hidden_data must be decoded hidden content if found, otherwise \"none\"."
        + context_block
    )
    try:
        raw_output = _run_ollama_raw(prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
        normalized = _normalize_verification_result(raw_output)
        if _looks_instructional_or_chatty(raw_output) or (
            normalized["anomalies"] == ["verification output was unstructured"]
        ):
            repair_prompt = (
                "Your previous answer was invalid because it included assistant-style prose, code, or instructions instead of strict JSON. "
                + PROMPT_CONTRACT +
                "Do not write scripts, lists of IDs, or any follow-up text. "
                "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
                "summary must be 3 to 8 words naming only the general document type. "
                "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
                "hidden_data must be decoded hidden content if found, otherwise \"none\". "
                "Previous invalid answer: "
                + raw_output[:1200]
                + context_block
            )
            normalized = _normalize_verification_result(
                _run_ollama_raw(repair_prompt, timeout=OLLAMA_VERIFY_TIMEOUT)
            )
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
        "You are analyzing ONE file. The metadata, head/tail bytes, and extracted strings are views of the SAME file. "
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
        if _looks_instructional_or_chatty(raw_output):
            repair_prompt = (
                "Your previous answer was invalid because it included assistant-style prose, code, or follow-up text instead of strict JSON. "
                + PROMPT_CONTRACT +
                "Return STRICT JSON ONLY with keys: summary, anomalies, hidden_indicators, hidden_data, evidence. "
                "summary must be 3 to 8 words naming only the general document type. "
                "anomalies, hidden_indicators, and evidence must be arrays of short strings or the single string \"none found\". "
                "hidden_data must be decoded hidden content if found, otherwise \"none\". "
                "Previous invalid answer: "
                + raw_output[:1200]
                + context_block
            )
            normalized_output = _normalize_model_output(
                _run_ollama_raw(repair_prompt, timeout=OLLAMA_BROAD_TIMEOUT)
            )
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

def analyze_with_known_techniques(context: dict, extra_guidance: str = "") -> str:
    context_block = (
        f"\n\nFILE CONTEXT\n"
        f"Filename: {context['filename']}\n"
        f"Size (bytes): {context['size_bytes']}\n"
        f"SHA256: {context['sha256']}\n"
        f"MIME guess: {context['mime_guess']}\n"
        f"Head hex: {context['bytecode_head_hex']}\n"
        f"Tail hex: {context['bytecode_tail_hex']}\n"
        f"Extracted strings (full file): {context['strings_full']}\n"
    )
    family_result, analysis_issues = _run_family_detection_pass(
        context_block,
        extra_guidance=extra_guidance,
    )
    candidate_families = family_result.get("candidate_families", "none found")
    if isinstance(candidate_families, str):
        candidate_family_list = [] if candidate_families == "none found" else [candidate_families]
    else:
        candidate_family_list = candidate_families

    verified_findings = {
        "summary": family_result.get("summary", "Financial or ledger-style tabular data."),
        "anomalies": "none found",
        "hidden_indicators": "none found",
        "hidden_data": "none",
        "evidence": family_result.get("evidence", "none found"),
    }
    if candidate_family_list:
        verified_findings, verification_issues = _run_family_verification_pass(
            context_block,
            candidate_family_list,
            extra_guidance=extra_guidance,
        )
        analysis_issues.extend(verification_issues)
    else:
        analysis_issues.append("family verification skipped because no trained-family candidates were flagged")

    broad = _run_broad_anomaly_pass(
        context_block,
        verified_findings,
        analysis_issues,
        extra_guidance=extra_guidance,
    )

    anomalies: list[str] = []
    hidden_indicators: list[str] = []
    evidence: list[str] = []
    hidden_data_values: list[str] = []

    for field_name, target in (
        ("anomalies", anomalies),
        ("hidden_indicators", hidden_indicators),
        ("evidence", evidence),
    ):
        value = verified_findings.get(field_name, "none found")
        if isinstance(value, list):
            target.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip().lower() not in {"", "none", "none found"}:
            target.append(value.strip())

    verified_hidden = verified_findings.get("hidden_data", "none")
    if isinstance(verified_hidden, list):
        hidden_data_values.extend(str(item).strip() for item in verified_hidden if str(item).strip().lower() != "none")
    else:
        verified_hidden = str(verified_hidden).strip()
        if verified_hidden and verified_hidden.lower() != "none":
            hidden_data_values.append(verified_hidden)

    for field_name, target in (
        ("anomalies", anomalies),
        ("hidden_indicators", hidden_indicators),
        ("evidence", evidence),
    ):
        value = broad.get(field_name, "none found")
        if isinstance(value, list):
            target.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip().lower() not in {"", "none", "none found"}:
            target.append(value.strip())

    broad_hidden = str(broad.get("hidden_data", "none")).strip()
    if broad_hidden and broad_hidden.lower() != "none":
        hidden_data_values.append(broad_hidden)

    if candidate_family_list:
        hidden_indicators.extend(f"candidate family flagged: {item}" for item in candidate_family_list)
    evidence.extend(analysis_issues)

    result = {
        "summary": str(
            verified_findings.get("summary")
            or broad.get("summary")
            or "Financial or ledger-style tabular data."
        ).splitlines()[0].strip() or "Financial or ledger-style tabular data.",
        "anomalies": _dedupe_items(anomalies) or "none found",
        "hidden_indicators": _dedupe_items(hidden_indicators) or "none found",
        "hidden_data": _dedupe_items(hidden_data_values) if hidden_data_values else "none",
        "evidence": _dedupe_items(evidence) or "none found",
    }
    return json.dumps(result, ensure_ascii=False)

def _set_job(job_id: str, **updates) -> None:
    with _jobs_lock:
        entry = _jobs.get(job_id, {})
        entry.update(updates)
        _jobs[job_id] = entry

def _run_job(job_id: str, dest: Path, prompt: str, filename: str) -> None:
    _set_job(job_id, status="running", started_at=time.time())
    try:
        context = build_file_context(dest)
        output = analyze_with_known_techniques(context, extra_guidance=prompt or "")
        _set_job(
            job_id,
            status="done",
            finished_at=time.time(),
            result={
                "status": "File received",
                "filename": filename,
                "llama_model": OLLAMA_MODEL,
                "llama_output": output,
            },
        )
    except Exception as exc:
        app.logger.exception("Ollama execution failed")
        _set_job(
            job_id,
            status="error",
            finished_at=time.time(),
            error=str(exc),
            result={
                "status": "File received",
                "filename": filename,
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
    if PREWARM_EACH_REQUEST and is_remote:
        _maybe_prewarm_async()

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
        return jsonify({
            "status": "File received",
            "filename": filename,
            "llama_model": OLLAMA_MODEL,
            "llama_output": output,
        }), 200
    except Exception as exc:
        app.logger.exception("Ollama execution failed")
        return jsonify({
            "status": "File received",
            "filename": filename,
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


print("Starting server...")
# serve(app, host="0.0.0.0", port=65432, channel_timeout=1000000, asyncore_loop_timeout=5, connection_limit=1000)
if PREWARM_ON_STARTUP:
    _maybe_prewarm_async()
app.run(host="0.0.0.0", port=65432)

