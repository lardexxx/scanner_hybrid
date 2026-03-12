# config.py

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BrowserConfig:
    headless: bool = False
    slow_mo: int = 0
    timeout: int = 15000  # ms
    wait_until: str = "load"  # load | domcontentloaded | networkidle


@dataclass
class RequestConfig:
    timeout: int = 10  # sec
    verify_ssl: bool = True
    allow_redirects: bool = True
    user_agent: str = "WebScanner/1.0"


@dataclass
class CrawlerConfig:
    max_depth: int = 3
    max_pages: int = 20
    follow_external: bool = False
    extract_forms: bool = True
    extract_js_links: bool = True


@dataclass
class XSSConfig:
    enabled: bool = True
    payloads: Optional[List[Dict[str, Any]]] = None
    max_attempts_per_param: int = 5
    dom_confirmation_enabled: bool = False
    dom_confirmation_only_raw: bool = True
    dom_confirmation_wait_ms: int = 1200
    include_informational: bool = False

    def __post_init__(self):
        if self.payloads is None:
            self.payloads = [
                {
                    "name": "html_script_tag",
                    "value": "<script>alert(1)</script>",
                    "contexts": ["html_text"],
                },
                {
                    "name": "attr_breakout",
                    "value": "onmouseover=alert(1)",
                    "contexts": ["attr"],
                },
                {
                    "name": "event_handler_breakout",
                    "value": "\";alert(1);//",
                    "contexts": ["event"],
                },
                {
                    "name": "js_sq_breakout",
                    "value": "';alert(1);//",
                    "contexts": ["js_string_sq"],
                },
                {
                    "name": "js_dq_breakout",
                    "value": "\";alert(1);//",
                    "contexts": ["js_string_dq"],
                },
                {
                    "name": "js_template_breakout",
                    "value": "`;alert(1);//",
                    "contexts": ["js_template"],
                },
                {
                    "name": "js_raw_inline",
                    "value": "alert(1)//",
                    "contexts": ["js_raw", "js"],
                },
                {
                    "name": "html_comment_breakout",
                    "value": "--><script>alert(1)</script>",
                    "contexts": ["html_comment"],
                },
            ]


@dataclass
class SQLiConfig:
    enabled: bool = True
    time_based_delay: int = 5
    payloads: Optional[List[Dict[str, Any] | str]] = None
    boolean_enabled: bool = True
    boolean_payload_pairs: Optional[List[Dict[str, Any]]] = None
    boolean_true_payloads: Optional[List[str]] = None
    boolean_false_payloads: Optional[List[str]] = None
    boolean_min_gap: float = 0.12
    baseline_samples: int = 3
    ignore_server_errors_for_heuristics: bool = True

    def __post_init__(self):
        if self.payloads is None:
            self.payloads = [
                {
                    "name": "generic_quote_or_true",
                    "value": "' OR '1'='1",
                    "techniques": ["error", "boolean"],
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["any"],
                },
                {
                    "name": "generic_numeric_or_true",
                    "value": "1 OR 1=1",
                    "techniques": ["boolean"],
                    "param_contexts": ["numeric", "unknown"],
                    "dialects": ["any"],
                },
                {
                    "name": "mysql_time_sleep",
                    "value": "' OR SLEEP(5)--",
                    "techniques": ["time"],
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["mysql", "any"],
                },
                {
                    "name": "postgres_time_sleep",
                    "value": "'; SELECT pg_sleep(5)--",
                    "techniques": ["time"],
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["postgres", "any"],
                },
                {
                    "name": "mssql_time_waitfor",
                    "value": "'; WAITFOR DELAY '0:0:5'--",
                    "techniques": ["time"],
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["mssql", "any"],
                },
                {
                    "name": "generic_union_probe",
                    "value": "' UNION SELECT NULL--",
                    "techniques": ["error"],
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["any"],
                },
            ]

        if self.boolean_payload_pairs is None:
            self.boolean_payload_pairs = [
                {
                    "name": "string_boolean_pair",
                    "true": "' OR '1'='1' -- ",
                    "false": "' OR '1'='2' -- ",
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["any"],
                },
                {
                    "name": "numeric_boolean_pair",
                    "true": "1 OR 1=1",
                    "false": "1 OR 1=2",
                    "param_contexts": ["numeric", "unknown"],
                    "dialects": ["any"],
                },
            ]

        # Legacy compatibility: accept old true/false lists if provided.
        if self.boolean_true_payloads and self.boolean_false_payloads:
            self.boolean_payload_pairs = []
            for idx, (true_payload, false_payload) in enumerate(
                zip(self.boolean_true_payloads, self.boolean_false_payloads)
            ):
                self.boolean_payload_pairs.append(
                    {
                        "name": f"legacy_pair_{idx}",
                        "true": str(true_payload),
                        "false": str(false_payload),
                        "param_contexts": ["unknown", "string", "numeric"],
                        "dialects": ["any"],
                    }
                )

        if self.boolean_true_payloads is None:
            self.boolean_true_payloads = [
                str(pair.get("true", ""))
                for pair in self.boolean_payload_pairs
                if str(pair.get("true", "")).strip()
            ]
        if self.boolean_false_payloads is None:
            self.boolean_false_payloads = [
                str(pair.get("false", ""))
                for pair in self.boolean_payload_pairs
                if str(pair.get("false", "")).strip()
            ]


@dataclass
class CSRFConfig:
    enabled: bool = True
    check_samesite: bool = True
    require_token: bool = True
    include_auth_forms: bool = False


@dataclass
class ScannerConfig:
    target_url: str
    use_browser: bool = True
    threads: int = 4

    request: RequestConfig = field(default_factory=RequestConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    xss: XSSConfig = field(default_factory=XSSConfig)
    sqli: SQLiConfig = field(default_factory=SQLiConfig)
    csrf: CSRFConfig = field(default_factory=CSRFConfig)
