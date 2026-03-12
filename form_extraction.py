from typing import List

from bs4 import BeautifulSoup

from models import Form, InputField


def extract_forms_from_soup(soup: BeautifulSoup, base_url: str) -> List[Form]:
    forms: List[Form] = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        method = form_tag.get("method", "GET").upper()
        enctype = (form_tag.get("enctype") or "application/x-www-form-urlencoded").strip()
        inputs: List[InputField] = []

        for control in form_tag.find_all(["input", "textarea", "select"]):
            if _is_disabled(control):
                continue

            name = (control.get("name") or "").strip()
            if not name:
                continue

            tag = control.name
            if tag == "input":
                input_type = (control.get("type") or "text").lower()
                if input_type in {"submit", "button", "reset", "file", "image"}:
                    continue
                if input_type in {"checkbox", "radio"} and not control.has_attr("checked"):
                    continue
                value = control.get("value")
                if value is None and input_type in {"checkbox", "radio"}:
                    value = "on"
                if value is None and input_type == "hidden":
                    value = ""
                inputs.append(
                    InputField(
                        name=name,
                        input_type=input_type,
                        value=value,
                    )
                )
                continue

            if tag == "textarea":
                inputs.append(
                    InputField(
                        name=name,
                        input_type="textarea",
                        value=control.text or "",
                    )
                )
                continue

            if tag == "select":
                inputs.append(
                    InputField(
                        name=name,
                        input_type="select",
                        value=_select_value(control),
                    )
                )

        forms.append(
            Form(
                action=action,
                method=method,
                inputs=inputs,
                source_url=base_url,
                enctype=enctype,
            )
        )

    return forms


def _is_disabled(control) -> bool:
    if control.has_attr("disabled"):
        return True

    for fieldset in control.find_parents("fieldset"):
        if not fieldset.has_attr("disabled"):
            continue
        legends = fieldset.find_all("legend", recursive=False)
        if legends and legends[0] in control.parents:
            continue
        return True

    return False


def _select_value(select_tag) -> str:
    options = select_tag.find_all("option")
    if not options:
        return ""

    selected = [option for option in options if option.has_attr("selected")]
    chosen = selected[0] if selected else options[0]
    value = chosen.get("value")
    if value is None:
        value = chosen.get_text(strip=True)
    return value or ""
