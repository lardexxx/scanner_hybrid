from typing import Dict, Set


SQL_DIALECT_MARKERS = {
    "mysql": (
        "you have an error in your sql syntax",
        "mysql",
        "mariadb",
    ),
    "postgres": (
        "postgresql",
        "pg_query",
        "pg::",
        "syntax error at or near",
    ),
    "sqlite": (
        "sqlite",
        "sqlite3::",
        "sqlite exception",
    ),
    "mssql": (
        "sqlserver",
        "microsoft ole db provider for sql server",
        "unclosed quotation mark",
        "odbc sql server driver",
    ),
    "oracle": (
        "ora-",
    ),
}


def detect_sql_error_markers(text: str) -> Dict[str, object]:
    lowered = (text or "").lower()
    dialects: Set[str] = set()
    markers: Set[str] = set()

    for dialect, pattern_list in SQL_DIALECT_MARKERS.items():
        for pattern in pattern_list:
            if pattern in lowered:
                dialects.add(dialect)
                markers.add(pattern)

    return {
        "has_sql_error": bool(markers),
        "dialects": dialects,
        "markers": markers,
    }


def derive_param_context(
    baseline_status: int,
    baseline_text: str,
    quote_status: int,
    quote_text: str,
    numeric_status: int,
    numeric_text: str,
) -> Dict[str, object]:
    baseline_error = detect_sql_error_markers(baseline_text)
    quote_error = detect_sql_error_markers(quote_text)
    numeric_error = detect_sql_error_markers(numeric_text)

    dialects: Set[str] = set()
    dialects.update(baseline_error["dialects"])
    dialects.update(quote_error["dialects"])
    dialects.update(numeric_error["dialects"])
    if not dialects:
        dialects.add("any")

    quote_status_shift = _status_shift(baseline_status, quote_status)
    numeric_status_shift = _status_shift(baseline_status, numeric_status)

    param_context = "unknown"
    if quote_error["has_sql_error"] and not numeric_error["has_sql_error"]:
        param_context = "string"
    elif numeric_error["has_sql_error"] and not quote_error["has_sql_error"]:
        param_context = "numeric"
    elif quote_status_shift and not numeric_status_shift:
        param_context = "string"
    elif numeric_status_shift and not quote_status_shift:
        param_context = "numeric"

    techniques: Set[str] = {"error", "boolean", "time"}
    if baseline_status >= 500:
        # Noisy 5xx baselines tend to poison boolean/time heuristics.
        techniques = {"error"}

    if quote_error["has_sql_error"] or numeric_error["has_sql_error"]:
        techniques.add("error")

    return {
        "param_context": param_context,
        "dialects": dialects,
        "techniques": techniques,
        "quote_error": bool(quote_error["has_sql_error"]),
        "numeric_error": bool(numeric_error["has_sql_error"]),
    }


def _status_shift(baseline_status: int, candidate_status: int) -> bool:
    if not baseline_status or not candidate_status:
        return False
    return baseline_status != candidate_status
