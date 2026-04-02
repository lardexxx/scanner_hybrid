import json
from typing import Any, Dict, Iterable, List, Tuple

from urllib.parse import parse_qs, urlparse

from models import Form, InputPoint, ObservedRequest


def build_navigation_request(
    url: str,
    source_page_url: str,
    source_kind: str = "navigation",
    method: str = "GET",
    status_code: int | None = None,
    headers: Dict[str, str] | None = None,
) -> ObservedRequest:
    # Навигация по странице тоже является реальным запросом, который можно воспроизвести.
    parsed = urlparse(url)
    return ObservedRequest(
        source_page_url=source_page_url,
        source_kind=source_kind,
        method=method.upper(),
        url=url,
        resource_type="document",
        status_code=status_code,
        headers=headers or {},
        query_params=_normalize_param_mapping(parse_qs(parsed.query)),
    )


def extract_query_input_points(request: ObservedRequest) -> List[InputPoint]:
    points: List[InputPoint] = []
    for name, values in sorted((request.query_params or {}).items()):
        if not values:
            points.append(
                InputPoint(
                    kind="query",
                    source_page_url=request.source_page_url,
                    request_url=request.url,
                    method=request.method,
                    locator=name,
                    original_value=None,
                    source_kind=request.source_kind,
                    content_type=request.content_type,
                )
            )
            continue

        for value in values:
            points.append(
                InputPoint(
                    kind="query",
                    source_page_url=request.source_page_url,
                    request_url=request.url,
                    method=request.method,
                    locator=name,
                    original_value=value,
                    source_kind=request.source_kind,
                    content_type=request.content_type,
                )
            )

    return dedupe_input_points(points)


def extract_form_input_points(form: Form) -> List[InputPoint]:
    points: List[InputPoint] = []
    request_url = form.absolute_action()
    method = (form.method or "GET").upper()

    for field in form.inputs:
        name = str(field.name or "").strip()
        if not name:
            continue
        points.append(
            InputPoint(
                kind="form_field",
                source_page_url=form.source_url,
                request_url=request_url,
                method=method,
                locator=name,
                original_value=field.value,
                source_kind="form",
                content_type=form.enctype,
            )
        )

    return dedupe_input_points(points)


def extract_json_input_points(request: ObservedRequest) -> List[InputPoint]:
    if request.json_body is None:
        return []

    points: List[InputPoint] = []
    for path, value in iter_json_leaf_values(request.json_body):
        points.append(
            InputPoint(
                kind="json_field",
                source_page_url=request.source_page_url,
                request_url=request.url,
                method=request.method,
                locator=path,
                original_value=value,
                source_kind=request.source_kind,
                content_type=request.content_type,
            )
        )

    return dedupe_input_points(points)


def iter_json_leaf_values(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    # Для proof-движков важны только конечные поля JSON, которые можно менять по одному.
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            yield from iter_json_leaf_values(item, child_path)
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            child_path = f"{path}[{index}]"
            yield from iter_json_leaf_values(item, child_path)
        return

    yield path, value


def parse_request_body(
    raw_body: str | None,
    content_type: str | None,
) -> tuple[Dict[str, List[str]], Any]:
    normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
    if not raw_body:
        return {}, None

    if normalized_content_type == "application/json":
        try:
            return {}, json.loads(raw_body)
        except json.JSONDecodeError:
            return {}, None

    if normalized_content_type == "application/x-www-form-urlencoded":
        return _normalize_param_mapping(parse_qs(raw_body)), None

    return {}, None


def dedupe_requests(requests: List[ObservedRequest]) -> List[ObservedRequest]:
    unique: List[ObservedRequest] = []
    seen: set[tuple[str, str, str, str]] = set()

    for request in requests:
        key = (
            request.method.upper(),
            request.url,
            request.source_kind,
            request.raw_body or "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(request)

    return unique


def dedupe_input_points(points: List[InputPoint]) -> List[InputPoint]:
    unique: List[InputPoint] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()

    for point in points:
        key = (
            point.kind,
            point.source_page_url,
            point.request_url,
            point.method.upper(),
            point.locator,
            repr(point.original_value),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(point)

    return unique


def _normalize_param_mapping(raw_mapping: Dict[str, Any]) -> Dict[str, List[str]]:
    normalized: Dict[str, List[str]] = {}
    for key, value in raw_mapping.items():
        if isinstance(value, list):
            normalized[str(key)] = [str(item) for item in value]
        else:
            normalized[str(key)] = [str(value)]
    return normalized
