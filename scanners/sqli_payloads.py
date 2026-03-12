from typing import Any, Dict, Iterable, List, Set


def normalize_payloads(payloads: Iterable[Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for entry in payloads:
        if isinstance(entry, dict):
            value = str(entry.get("value", "")).strip()
            if not value:
                continue

            normalized.append(
                {
                    "name": str(entry.get("name", value[:40])),
                    "value": value,
                    "techniques": _normalize_keywords(
                        entry.get("techniques", ["error", "boolean", "time"])
                    ),
                    "param_contexts": _normalize_keywords(
                        entry.get("param_contexts", entry.get("contexts", ["unknown"]))
                    ),
                    "dialects": _normalize_keywords(entry.get("dialects", ["any"])),
                }
            )
            continue

        if isinstance(entry, str) and entry.strip():
            normalized.append(
                {
                    "name": entry[:40],
                    "value": entry,
                    "techniques": ["error", "time"],
                    "param_contexts": ["unknown", "string", "numeric"],
                    "dialects": ["any"],
                }
            )

    return normalized


def normalize_boolean_pairs(pairs: Iterable[Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for index, entry in enumerate(pairs):
        if isinstance(entry, dict):
            true_payload = str(entry.get("true", "")).strip()
            false_payload = str(entry.get("false", "")).strip()
            if not true_payload or not false_payload:
                continue
            normalized.append(
                {
                    "name": str(entry.get("name", f"pair_{index}")),
                    "true": true_payload,
                    "false": false_payload,
                    "param_contexts": _normalize_keywords(
                        entry.get("param_contexts", ["unknown", "string", "numeric"])
                    ),
                    "dialects": _normalize_keywords(entry.get("dialects", ["any"])),
                }
            )
            continue

        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            true_payload = str(entry[0]).strip()
            false_payload = str(entry[1]).strip()
            if not true_payload or not false_payload:
                continue
            normalized.append(
                {
                    "name": f"pair_{index}",
                    "true": true_payload,
                    "false": false_payload,
                    "param_contexts": ["unknown", "string", "numeric"],
                    "dialects": ["any"],
                }
            )

    return normalized


def select_payloads_by_context(
    payload_catalog: List[Dict[str, Any]],
    techniques: Set[str],
    param_context: str,
    dialects: Set[str],
) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    technique_filter = {t.strip().lower() for t in techniques if t.strip()}
    dialect_filter = {d.strip().lower() for d in dialects if d.strip()} or {"any"}
    param_context = (param_context or "unknown").strip().lower()

    for payload in payload_catalog:
        payload_techniques = set(payload.get("techniques", []))
        payload_contexts = set(payload.get("param_contexts", []))
        payload_dialects = set(payload.get("dialects", []))

        if technique_filter and payload_techniques and not technique_filter.intersection(
            payload_techniques
        ):
            continue
        if not _context_match(param_context, payload_contexts):
            continue
        if not _dialect_match(dialect_filter, payload_dialects):
            continue

        selected.append(payload)

    return selected


def select_boolean_pairs_by_context(
    pair_catalog: List[Dict[str, Any]],
    param_context: str,
    dialects: Set[str],
) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    dialect_filter = {d.strip().lower() for d in dialects if d.strip()} or {"any"}
    param_context = (param_context or "unknown").strip().lower()

    for pair in pair_catalog:
        pair_contexts = set(pair.get("param_contexts", []))
        pair_dialects = set(pair.get("dialects", []))
        if not _context_match(param_context, pair_contexts):
            continue
        if not _dialect_match(dialect_filter, pair_dialects):
            continue
        selected.append(pair)

    return selected


def _normalize_keywords(raw: Any) -> List[str]:
    if isinstance(raw, str):
        candidate = [raw]
    elif isinstance(raw, list):
        candidate = raw
    else:
        candidate = []

    normalized: List[str] = []
    seen: Set[str] = set()
    for item in candidate:
        value = str(item).strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _context_match(param_context: str, payload_contexts: Set[str]) -> bool:
    if not payload_contexts:
        return True
    if "unknown" in payload_contexts:
        return True
    if param_context == "unknown":
        return True
    return param_context in payload_contexts


def _dialect_match(candidate_dialects: Set[str], payload_dialects: Set[str]) -> bool:
    if not payload_dialects:
        return True
    if "any" in payload_dialects:
        return True
    if "any" in candidate_dialects:
        return True
    return bool(candidate_dialects.intersection(payload_dialects))
