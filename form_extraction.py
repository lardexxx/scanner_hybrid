from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from models import Form, InputField


def extract_forms_from_soup(soup: BeautifulSoup, base_url: str) -> List[Form]:
    # Извлекаем формы строго из уже полученного HTML без домыслов.
    forms: List[Form] = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        method = str(form_tag.get("method", "GET")).upper()
        enctype = str(
            form_tag.get("enctype") or "application/x-www-form-urlencoded"
        ).strip()
        inputs: List[InputField] = []
        submit_controls: List[InputField] = []

        for control in form_tag.find_all(["input", "textarea", "select", "button"]):
            if _is_disabled(control):
                continue

            name = str(control.get("name") or "").strip()
            if not name:
                continue

            tag_name = control.name
            if tag_name == "input":
                input_type = str(control.get("type") or "text").strip().lower()
                if input_type in {"reset", "file", "button"}:
                    continue
                if input_type in {"submit", "image"}:
                    submit_controls.append(
                        InputField(
                            name=name,
                            input_type=input_type,
                            value=control.get("value") or "",
                        )
                    )
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

            if tag_name == "textarea":
                inputs.append(
                    InputField(
                        name=name,
                        input_type="textarea",
                        value=control.text or "",
                    )
                )
                continue

            if tag_name == "select":
                inputs.append(
                    InputField(
                        name=name,
                        input_type="select-multiple" if control.has_attr("multiple") else "select",
                        value=_select_value(control),
                    )
                )
                continue

            if tag_name == "button":
                button_type = str(control.get("type") or "submit").strip().lower()
                if button_type == "reset":
                    continue
                if button_type == "submit":
                    submit_controls.append(
                        InputField(
                            name=name,
                            input_type="button:submit",
                            value=control.get("value") or control.get_text(strip=True) or "",
                        )
                    )

        forms.append(
            Form(
                action=action,
                method=method,
                inputs=inputs,
                source_url=base_url,
                enctype=enctype,
                submit_controls=submit_controls,
            )
        )

    return forms


def build_form_data(
    form: Form,
    remove_fields: Optional[List[str]] = None,
    override_fields: Optional[Dict[str, Any]] = None,
    submit_control_name: Optional[str] = None,
    submit_control_index: Optional[int] = None,
) -> Dict[str, Any]:
    # Строим воспроизводимое тело формы из уже найденной структуры.
    data: Dict[str, Any] = {}
    remove_set = set(remove_fields or [])
    overrides = dict(override_fields or {})

    for field in form.inputs:
        name = str(field.name or "").strip()
        if not name or name in remove_set:
            continue
        if name in overrides:
            _add_field_value(data, name, overrides[name])
            continue
        if field.value is not None:
            _add_field_value(data, name, field.value)
            continue

        input_type = str(field.input_type or "").strip().lower()
        if input_type in {"hidden", "select", "select-multiple", "textarea"}:
            _add_field_value(data, name, "")
        else:
            _add_field_value(data, name, "test")

    submit_control = _pick_submit_control(
        submit_controls=form.submit_controls or [],
        remove_set=remove_set,
        overrides=overrides,
        submit_control_name=submit_control_name,
        submit_control_index=submit_control_index,
    )
    if submit_control is not None:
        submit_name = str(submit_control.name or "").strip()
        if submit_name in overrides:
            _add_field_value(data, submit_name, overrides[submit_name])
        else:
            _add_field_value(
                data,
                submit_name,
                submit_control.value if submit_control.value is not None else "",
            )

    return data


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


def _select_value(select_tag) -> str | List[str] | None:
    options = [
        option
        for option in select_tag.find_all("option")
        if not _is_option_disabled(option)
    ]
    if not options:
        return [] if select_tag.has_attr("multiple") else None

    selected = [option for option in options if option.has_attr("selected")]
    if select_tag.has_attr("multiple"):
        return [_option_value(option) for option in selected]

    chosen = selected[0] if selected else options[0]
    return _option_value(chosen)


def _is_option_disabled(option) -> bool:
    if option.has_attr("disabled"):
        return True

    for optgroup in option.find_parents("optgroup"):
        if optgroup.has_attr("disabled"):
            return True

    return False


def _option_value(option) -> str:
    value = option.get("value")
    if value is None:
        value = option.get_text(strip=True)
    return value or ""


def _add_field_value(data: Dict[str, Any], name: str, value: Any):
    values = _normalize_field_values(value)
    if not values:
        return

    existing = data.get(name)
    if existing is None:
        data[name] = values[0] if len(values) == 1 else values
        return

    if isinstance(existing, list):
        existing.extend(values)
        return

    data[name] = [existing, *values]


def _pick_submit_control(
    submit_controls: List[InputField],
    remove_set: set[str],
    overrides: Dict[str, Any],
    submit_control_name: Optional[str] = None,
    submit_control_index: Optional[int] = None,
) -> InputField | None:
    candidates: List[InputField] = []
    for control in submit_controls:
        name = str(control.name or "").strip()
        if not name or name in remove_set:
            continue
        candidates.append(control)

    if not candidates:
        return None

    if submit_control_index is not None and 0 <= submit_control_index < len(candidates):
        return candidates[submit_control_index]

    if submit_control_name:
        for control in candidates:
            if str(control.name or "").strip() == submit_control_name:
                return control

    for control in candidates:
        if str(control.name or "").strip() in overrides:
            return control

    return candidates[0]


def _normalize_field_values(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value is None:
        return []
    return [str(value)]
