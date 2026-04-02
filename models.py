from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from urllib.parse import urljoin


@dataclass
class InputField:
    # Одно поле HTML-формы.
    name: str
    input_type: str
    value: str | List[str] | None = None


@dataclass
class Form:
    # Наблюдаемая HTML-форма.
    action: str
    method: str
    inputs: List[InputField]
    source_url: str
    enctype: str = "application/x-www-form-urlencoded"
    submit_controls: Optional[List[InputField]] = None
    dom_index: int | None = None

    def __post_init__(self):
        if self.submit_controls is None:
            self.submit_controls = []

    def absolute_action(self) -> str:
        return urljoin(self.source_url, self.action)


@dataclass
class ObservedRequest:
    # Реально наблюденный HTTP-запрос, который потом можно воспроизвести.
    source_page_url: str
    source_kind: str
    method: str
    url: str
    resource_type: Optional[str] = None
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    headers: Optional[Dict[str, str]] = None
    query_params: Optional[Dict[str, List[str]]] = None
    form_fields: Optional[Dict[str, List[str]]] = None
    json_body: Any = None
    raw_body: Optional[str] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.query_params is None:
            self.query_params = {}
        if self.form_fields is None:
            self.form_fields = {}


@dataclass
class InputPoint:
    # Подтвержденная точка ввода в реальном запросе.
    kind: str
    source_page_url: str
    request_url: str
    method: str
    locator: str
    original_value: Any = None
    source_kind: str = "unknown"
    content_type: Optional[str] = None


@dataclass
class Page:
    # Загруженная страница с артефактами discovery.
    url: str
    status_code: int
    content: str
    links: Optional[List[str]] = None
    forms: Optional[List[Form]] = None
    depth: int = 0
    observed_requests: Optional[List[ObservedRequest]] = None
    input_points: Optional[List[InputPoint]] = None

    def __post_init__(self):
        if self.links is None:
            self.links = []
        if self.forms is None:
            self.forms = []
        if self.observed_requests is None:
            self.observed_requests = []
        if self.input_points is None:
            self.input_points = []


@dataclass
class SQLiFinding:
    url: str
    method: str
    param: str
    payload: str
    technique: str
    response_time: float
    evidence: str
    confidence: str
    proof_status: str = "proven"
    trials_run: int = 1
    successful_trials: int = 1


@dataclass
class ScanResult:
    # Общий результат запуска сканера.
    target: str
    pages_scanned: int
    sqli_findings: Optional[List[SQLiFinding]] = None

    def __post_init__(self):
        if self.sqli_findings is None:
            self.sqli_findings = []

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "pages_scanned": self.pages_scanned,
            "sqli_count": len(self.sqli_findings),
        }
