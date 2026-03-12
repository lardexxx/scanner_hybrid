from typing import Dict, List, Optional

from models import Form


CSRF_KEYWORDS = (
    "csrf",
    "xsrf",
    "_token",
    "token",
    "authenticity_token",
    "csrfmiddlewaretoken",
    "__requestverificationtoken",
)

STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

AUTH_HINTS = ("login", "signin", "auth", "password", "pass", "reset", "register")
SEARCH_HINTS = ("search", "query", "q", "find")


def find_token_fields(form: Form) -> List[str]:
    hits: List[str] = []
    for inp in form.inputs:
        name = (inp.name or "").strip()
        if not name:
            continue
        lowered = name.lower()
        if any(keyword in lowered for keyword in CSRF_KEYWORDS):
            hits.append(name)
    return hits


def classify_form(form: Form) -> Dict[str, object]:
    method = (form.method or "GET").upper()
    action = form.absolute_action()
    token_fields = find_token_fields(form)
    joined = _form_text(form)

    return {
        "method": method,
        "action": action,
        "is_state_changing": method in STATE_CHANGING_METHODS,
        "token_fields": token_fields,
        "has_token": bool(token_fields),
        "is_auth_like": any(hint in joined for hint in AUTH_HINTS),
        "is_search_like": any(hint in joined for hint in SEARCH_HINTS),
    }


def build_form_data(
    form: Form,
    remove_fields: Optional[List[str]] = None,
    override_fields: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    data: Dict[str, str] = {}
    remove_set = set(remove_fields or [])
    overrides = dict(override_fields or {})

    for inp in form.inputs:
        name = (inp.name or "").strip()
        if not name:
            continue
        if name in remove_set:
            continue
        if name in overrides:
            data[name] = overrides[name]
            continue
        if inp.value is not None:
            data[name] = inp.value
            continue

        input_type = (inp.input_type or "").strip().lower()
        if input_type in {"hidden", "select", "textarea"}:
            data[name] = ""
        else:
            data[name] = "test"

    return data


def _form_text(form: Form) -> str:
    parts = [(form.action or "").lower()]
    for inp in form.inputs:
        name = (inp.name or "").strip().lower()
        if name:
            parts.append(name)
    return " ".join(parts)
