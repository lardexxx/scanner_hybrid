from typing import Callable, Dict, List

from scanners.csrf_checks import looks_like_csrf_rejection, response_is_close


def probe_missing_token(
    method: str,
    action: str,
    baseline_data: Dict[str, str],
    token_fields: List[str],
    sender: Callable[[str, str, Dict[str, str]], object],
    min_len_ratio: float = 0.88,
    min_similarity: float = 0.90,
) -> Dict[str, object]:
    no_token_data = {
        key: value for key, value in baseline_data.items() if key not in set(token_fields)
    }

    baseline_resp = sender(method, action, baseline_data)
    no_token_resp = sender(method, action, no_token_data)

    if baseline_resp.status_code == 0 or no_token_resp.status_code == 0:
        return {"bypass_possible": False, "evidence": "request_error"}
    if baseline_resp.status_code >= 500 or no_token_resp.status_code >= 500:
        return {"bypass_possible": False, "evidence": "server_error"}
    if looks_like_csrf_rejection(no_token_resp.text, no_token_resp.status_code):
        return {"bypass_possible": False, "evidence": "csrf_rejection_detected"}

    is_close = response_is_close(
        baseline_text=baseline_resp.text,
        baseline_status=baseline_resp.status_code,
        candidate_text=no_token_resp.text,
        candidate_status=no_token_resp.status_code,
        min_len_ratio=min_len_ratio,
        min_similarity=min_similarity,
    )
    if not is_close:
        return {"bypass_possible": False, "evidence": "response_drift"}

    return {
        "bypass_possible": True,
        "evidence": (
            "missing-token request matched baseline "
            f"(status={baseline_resp.status_code}/{no_token_resp.status_code})"
        ),
    }


def probe_tampered_token(
    method: str,
    action: str,
    baseline_data: Dict[str, str],
    token_fields: List[str],
    sender: Callable[[str, str, Dict[str, str]], object],
    min_len_ratio: float = 0.88,
    min_similarity: float = 0.90,
) -> Dict[str, object]:
    tampered_data = dict(baseline_data)
    for token_name in token_fields:
        if token_name in tampered_data:
            tampered_data[token_name] = "tampered_csrf_token"

    baseline_resp = sender(method, action, baseline_data)
    tampered_resp = sender(method, action, tampered_data)

    if baseline_resp.status_code == 0 or tampered_resp.status_code == 0:
        return {"bypass_possible": False, "evidence": "request_error"}
    if baseline_resp.status_code >= 500 or tampered_resp.status_code >= 500:
        return {"bypass_possible": False, "evidence": "server_error"}
    if looks_like_csrf_rejection(tampered_resp.text, tampered_resp.status_code):
        return {"bypass_possible": False, "evidence": "csrf_rejection_detected"}

    is_close = response_is_close(
        baseline_text=baseline_resp.text,
        baseline_status=baseline_resp.status_code,
        candidate_text=tampered_resp.text,
        candidate_status=tampered_resp.status_code,
        min_len_ratio=min_len_ratio,
        min_similarity=min_similarity,
    )
    if not is_close:
        return {"bypass_possible": False, "evidence": "response_drift"}

    return {
        "bypass_possible": True,
        "evidence": (
            "tampered-token request matched baseline "
            f"(status={baseline_resp.status_code}/{tampered_resp.status_code})"
        ),
    }
