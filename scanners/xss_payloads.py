from typing import Any, Dict, Iterable, List, Set


def normalize_payloads(payloads: Iterable[Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for entry in payloads:
        if isinstance(entry, dict):
            value = str(entry.get("value", "")).strip()
            if not value:
                continue

            contexts = entry.get("contexts", [])
            if not isinstance(contexts, list):
                contexts = []

            normalized.append(
                {
                    "name": str(entry.get("name", value[:40])),
                    "value": value,
                    "contexts": [str(ctx).strip() for ctx in contexts if str(ctx).strip()],
                }
            )
            continue

        # Minimal legacy compatibility, but dict format is the primary mode.
        if isinstance(entry, str) and entry.strip():
            normalized.append(
                {
                    "name": entry[:40],
                    "value": entry,
                    "contexts": ["html_text", "attr", "event", "js"],
                }
            )

    return normalized


def expand_context_aliases(contexts: Set[str]) -> Set[str]:
    expanded = set(contexts)

    for ctx in list(contexts):
        if ctx in {"js_string_sq", "js_string_dq", "js_template", "js_raw"}:
            expanded.add("js")
        if ctx == "event":
            expanded.add("attr")
            expanded.add("js")

    return expanded


def select_payloads_by_context(
    payload_catalog: List[Dict[str, Any]],
    detected_contexts: Set[str],
) -> List[Dict[str, Any]]:
    if not detected_contexts:
        return []

    detected_expanded = expand_context_aliases(detected_contexts)
    selected: List[Dict[str, Any]] = []

    for payload in payload_catalog:
        payload_contexts = set(payload.get("contexts", []))
        payload_expanded = expand_context_aliases(payload_contexts)
        if detected_expanded.intersection(payload_expanded):
            selected.append(payload)

    return selected
