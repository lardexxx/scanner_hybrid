from typing import Any, Dict, Iterable, List, Set


def normalize_error_checks(checks: Iterable[Any]) -> List[Dict[str, Any]]:
    # Приводим error-проверки к одному формату.
    normalized: List[Dict[str, Any]] = []

    for entry in checks:
        if isinstance(entry, dict):
            value = str(entry.get("value", "")).strip()
            if not value:
                continue
            normalized.append(
                {
                    "name": str(entry.get("name", value[:40])),
                    "value": value,
                    "param_contexts": _normalize_keywords(
                        entry.get("param_contexts", ["unknown"])
                    ),
                    "dialects": _normalize_keywords(entry.get("dialects", ["any"])),
                }
            )
            continue

        if isinstance(entry, str) and entry.strip():
            normalized.append(
                {
                    "name": entry[:40],
                    "value": entry.strip(),
                    "param_contexts": ["unknown", "string", "numeric"],
                    "dialects": ["any"],
                }
            )

    return normalized


def normalize_boolean_checks(checks: Iterable[Any]) -> List[Dict[str, Any]]:
    # Для boolean-проверок важны именно пары true/false.
    normalized: List[Dict[str, Any]] = []

    for index, entry in enumerate(checks):
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


def normalize_time_checks(checks: Iterable[Any]) -> List[Dict[str, Any]]:
    # Time-проверка хранит payload с задержкой и, по возможности, control.
    normalized: List[Dict[str, Any]] = []

    for entry in checks:
        if isinstance(entry, dict):
            delay_payload = str(entry.get("delay", "")).strip()
            control_payload = str(entry.get("control", "")).strip()
            if not delay_payload:
                continue
            normalized.append(
                {
                    "name": str(entry.get("name", delay_payload[:40])),
                    "delay": delay_payload,
                    "control": control_payload or None,
                    "param_contexts": _normalize_keywords(
                        entry.get("param_contexts", ["unknown"])
                    ),
                    "dialects": _normalize_keywords(entry.get("dialects", ["any"])),
                }
            )
            continue

        if isinstance(entry, str) and entry.strip():
            normalized.append(
                {
                    "name": entry[:40],
                    "delay": entry.strip(),
                    "control": None,
                    "param_contexts": ["unknown", "string"],
                    "dialects": ["any"],
                }
            )

    return normalized


def select_error_checks_by_context(
    check_catalog: List[Dict[str, Any]],
    param_context: str,
    candidate_dialects: Set[str],
) -> List[Dict[str, Any]]:
    return _select_checks(check_catalog, param_context, candidate_dialects)


def select_boolean_checks_by_context(
    check_catalog: List[Dict[str, Any]],
    param_context: str,
    candidate_dialects: Set[str],
) -> List[Dict[str, Any]]:
    return _select_checks(check_catalog, param_context, candidate_dialects)


def select_time_checks_by_context(
    check_catalog: List[Dict[str, Any]],
    param_context: str,
    candidate_dialects: Set[str],
) -> List[Dict[str, Any]]:
    return _select_checks(check_catalog, param_context, candidate_dialects)


def _select_checks(
    check_catalog: List[Dict[str, Any]],
    param_context: str,
    candidate_dialects: Set[str],
) -> List[Dict[str, Any]]:
    # Сначала ищем точные совпадения, затем откатываемся к universal/unknown.
    selected: List[Dict[str, Any]] = []
    dialect_filter = {
        value.strip().lower() for value in candidate_dialects if value.strip()
    } or {"any"}
    context = (param_context or "unknown").strip().lower()

    for check in check_catalog:
        check_contexts = set(check.get("param_contexts", []))
        check_dialects = set(check.get("dialects", []))
        if not _context_match(context, check_contexts):
            continue
        if not _dialect_match(dialect_filter, check_dialects):
            continue
        selected.append(check)

    if selected:
        return selected

    return [
        check
        for check in check_catalog
        if "unknown" in set(check.get("param_contexts", []))
        and _dialect_match(dialect_filter, set(check.get("dialects", [])))
    ]


def _normalize_keywords(raw: Any) -> List[str]:
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list):
        values = raw
    else:
        values = []

    normalized: List[str] = []
    seen: Set[str] = set()
    for item in values:
        value = str(item).strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _context_match(param_context: str, check_contexts: Set[str]) -> bool:
    if not check_contexts:
        return True
    if "unknown" in check_contexts:
        return True
    if param_context == "unknown":
        return True
    return param_context in check_contexts


def _dialect_match(candidate_dialects: Set[str], check_dialects: Set[str]) -> bool:
    if not check_dialects:
        return True
    if "any" in check_dialects:
        return True
    if "any" in candidate_dialects:
        return True
    return bool(candidate_dialects.intersection(check_dialects))


# Legacy-алиасы, чтобы не ломать старые импорты.
normalize_payloads = normalize_error_checks
normalize_boolean_pairs = normalize_boolean_checks
select_payloads_by_context = select_error_checks_by_context
select_boolean_pairs_by_context = select_boolean_checks_by_context
