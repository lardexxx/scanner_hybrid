from difflib import SequenceMatcher
from typing import Dict, List


REJECTION_PATTERNS = (
    "csrf",
    "xsrf",
    "forbidden",
    "invalid token",
    "request verification failed",
    "token mismatch",
    "origin",
    "referer",
)


def looks_like_csrf_rejection(text: str, status_code: int) -> bool:
    if status_code in (401, 403):
        return True

    lowered = (text or "").lower()
    return any(pattern in lowered for pattern in REJECTION_PATTERNS)


def safe_ratio(a: int, b: int) -> float:
    if a == 0 or b == 0:
        return 0.0
    return min(a, b) / max(a, b)


def similarity_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def response_is_close(
    baseline_text: str,
    baseline_status: int,
    candidate_text: str,
    candidate_status: int,
    min_len_ratio: float = 0.88,
    min_similarity: float = 0.90,
) -> bool:
    if baseline_status != candidate_status:
        return False
    if safe_ratio(len(candidate_text), len(baseline_text)) < min_len_ratio:
        return False
    if similarity_ratio(baseline_text, candidate_text) < min_similarity:
        return False
    return True


def detect_samesite_issue(headers: Dict[str, str]) -> bool:
    raw = headers.get("Set-Cookie", "")
    if not raw:
        return False

    for cookie in split_set_cookie_header(raw):
        lowered = cookie.lower()
        if "samesite" not in lowered:
            return True
        if "samesite=none" in lowered and "secure" not in lowered:
            return True
    return False


def split_set_cookie_header(raw: str) -> List[str]:
    if not raw:
        return []

    # Keep commas inside Expires=... intact while splitting cookies.
    parts: List[str] = []
    chunk: List[str] = []
    i = 0
    in_expires = False
    lowered = raw.lower()

    while i < len(raw):
        ch = raw[i]

        if lowered[i : i + 8] == "expires=":
            in_expires = True

        if ch == "," and not in_expires:
            cookie = "".join(chunk).strip()
            if cookie:
                parts.append(cookie)
            chunk = []
            i += 1
            continue

        if ch == ";" and in_expires:
            in_expires = False

        chunk.append(ch)
        i += 1

    tail = "".join(chunk).strip()
    if tail:
        parts.append(tail)

    return parts
