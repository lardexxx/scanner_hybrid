# models.py

from dataclasses import dataclass
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse


# ===============================
# Page & Crawling Models
# ===============================

@dataclass
class InputField:
    name: str
    input_type: str
    value: Optional[str] = None


@dataclass
class Form:
    action: str
    method: str
    inputs: List[InputField]
    source_url: str
    enctype: str = "application/x-www-form-urlencoded"

    def absolute_action(self) -> str:
        return urljoin(self.source_url, self.action)


@dataclass
class Page:
    url: str
    status_code: int
    content: str
    links: Optional[List[str]] = None
    forms: Optional[List[Form]] = None
    depth: int = 0

    def __post_init__(self):
        if self.links is None:
            self.links = []
        if self.forms is None:
            self.forms = []


# ===============================
# Reflection / XSS Models
# ===============================

@dataclass
class ReflectionLocation:
    location_type: str      # html_text | attr | event | script | comment
    tag_name: Optional[str]
    attribute_name: Optional[str]


@dataclass
class ReflectedContext:
    context: str
    marker: str
    tag_name: Optional[str]
    attribute_name: Optional[str]
    quote_type: Optional[str]
    snippet: str
    start_offset: int


@dataclass
class XSSFinding:
    url: str
    method: str
    param: str
    payload: str
    payload_name: str
    reflected_as: str       # raw | html_escaped | js_escaped | none
    reflection_mode: str    # raw | html_escaped | js_escaped | none
    confidence: str         # info | low | medium | high
    status_code: int
    reflection_locations: List[ReflectionLocation]
    detected_contexts: List[ReflectedContext]
    evidence_snippet: str


# ===============================
# SQLi Models
# ===============================

@dataclass
class SQLiFinding:
    url: str
    method: str
    param: str
    payload: str
    technique: str          # error | boolean | time
    response_time: float
    evidence: str
    confidence: str         # low | medium | high


# ===============================
# CSRF Models
# ===============================

@dataclass
class CSRFFinding:
    url: str
    form_action: str
    method: str
    missing_token: bool
    samesite_issue: bool
    confidence: str


# ===============================
# Scan Result Aggregation
# ===============================

@dataclass
class ScanResult:
    target: str
    pages_scanned: int
    xss_findings: Optional[List[XSSFinding]] = None
    sqli_findings: Optional[List[SQLiFinding]] = None
    csrf_findings: Optional[List[CSRFFinding]] = None

    def __post_init__(self):
        if self.xss_findings is None:
            self.xss_findings = []
        if self.sqli_findings is None:
            self.sqli_findings = []
        if self.csrf_findings is None:
            self.csrf_findings = []

    def summary(self) -> Dict:
        return {
            "target": self.target,
            "pages_scanned": self.pages_scanned,
            "xss_count": len(self.xss_findings),
            "sqli_count": len(self.sqli_findings),
            "csrf_count": len(self.csrf_findings),
        }
