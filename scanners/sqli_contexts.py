from typing import Dict, Set


SQL_ERROR_HINTS = {
    "mysql": (
        "you have an error in your sql syntax",
        "mariadb",
        "warning: mysql",
    ),
    "postgres": (
        "postgresql",
        "syntax error at or near",
        "pg_query",
    ),
    "sqlite": (
        "sqlite",
        "sqlite3::",
        "sqlite exception",
    ),
    "mssql": (
        "unclosed quotation mark",
        "odbc sql server driver",
        "microsoft ole db provider for sql server",
    ),
    "oracle": (
        "ora-",
    ),
}


def detect_sql_error_hints(text: str) -> Dict[str, object]:
    # Возвращаем только наблюдаемые подсказки, а не "истину" о диалекте.
    lowered = (text or "").lower()
    candidate_dialects: Set[str] = set()
    matched_markers: Set[str] = set()

    for dialect, patterns in SQL_ERROR_HINTS.items():
        for pattern in patterns:
            if pattern in lowered:
                candidate_dialects.add(dialect)
                matched_markers.add(pattern)

    return {
        "has_sql_error_hint": bool(matched_markers),
        "candidate_dialects": candidate_dialects,
        "matched_markers": matched_markers,
    }


def derive_param_context(
    baseline_status: int,
    baseline_text: str,
    quote_status: int,
    quote_text: str,
    numeric_status: int,
    numeric_text: str,
) -> Dict[str, object]:
    baseline_hints = detect_sql_error_hints(baseline_text)
    quote_hints = detect_sql_error_hints(quote_text)
    numeric_hints = detect_sql_error_hints(numeric_text)

    candidate_dialects: Set[str] = set()
    candidate_dialects.update(baseline_hints["candidate_dialects"])
    candidate_dialects.update(quote_hints["candidate_dialects"])
    candidate_dialects.update(numeric_hints["candidate_dialects"])
    if not candidate_dialects:
        candidate_dialects.add("any")

    quote_status_shift = _status_shift(baseline_status, quote_status)
    numeric_status_shift = _status_shift(baseline_status, numeric_status)

    param_context = "unknown"
    if quote_hints["has_sql_error_hint"] and not numeric_hints["has_sql_error_hint"]:
        param_context = "string"
    elif numeric_hints["has_sql_error_hint"] and not quote_hints["has_sql_error_hint"]:
        param_context = "numeric"
    elif quote_status_shift and not numeric_status_shift:
        param_context = "string"
    elif numeric_status_shift and not quote_status_shift:
        param_context = "numeric"

    baseline_is_server_error = 500 <= baseline_status < 600

    return {
        "param_context": param_context,
        "candidate_dialects": candidate_dialects,
        "matched_markers": set(quote_hints["matched_markers"]).union(
            numeric_hints["matched_markers"]
        ),
        "baseline_status": baseline_status,
        "baseline_is_server_error": baseline_is_server_error,
        "blind_proof_allowed": not baseline_is_server_error,
        "error_proof_allowed": True,
    }


def _status_shift(baseline_status: int, candidate_status: int) -> bool:
    if not baseline_status or not candidate_status:
        return False
    return baseline_status != candidate_status
