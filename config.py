from dataclasses import dataclass
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
class SQLiConfig:
    enabled: bool = True
    time_based_delay: int = 5
    error_trials: int = 2
    error_checks: Optional[List[Dict[str, Any]]] = None
    boolean_enabled: bool = True
    boolean_trials: int = 3
    boolean_checks: Optional[List[Dict[str, Any]]] = None
    time_trials: int = 3
    time_checks: Optional[List[Dict[str, Any]]] = None
    payloads: Optional[List[Dict[str, Any]]] = None  # legacy
    boolean_payload_pairs: Optional[List[Dict[str, Any]]] = None  # legacy
    boolean_true_payloads: Optional[List[str]] = None  # legacy
    boolean_false_payloads: Optional[List[str]] = None  # legacy
    boolean_min_gap: float = 0.12
    baseline_samples: int = 3
    ignore_server_errors_for_heuristics: bool = True

    def __post_init__(self):
        if self.error_checks is None:
            self.error_checks = [
                {
                    "name": "generic_quote_break",
                    "value": "'",
                    "param_contexts": ["string", "unknown", "numeric"],
                    "dialects": ["any"],
                },
                {
                    "name": "generic_union_probe",
                    "value": "' UNION SELECT NULL--",
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["any"],
                },
            ]

        if self.boolean_checks is None:
            self.boolean_checks = [
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

        if self.time_checks is None:
            self.time_checks = [
                {
                    "name": "mysql_time_if_sleep",
                    "delay": "' OR IF(1=1,SLEEP(5),0)--",
                    "control": "' OR IF(1=2,SLEEP(5),0)--",
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["mysql"],
                },
                {
                    "name": "postgres_time_case_sleep",
                    "delay": "'; SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                    "control": "'; SELECT CASE WHEN 1=2 THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["postgres"],
                },
                {
                    "name": "mssql_time_waitfor",
                    "delay": "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
                    "control": "'; IF (1=2) WAITFOR DELAY '0:0:5'--",
                    "param_contexts": ["string", "unknown"],
                    "dialects": ["mssql"],
                },
            ]

        # Совместимость со старым смешанным catalog.
        if self.payloads:
            legacy_error_checks: List[Dict[str, Any]] = []
            legacy_time_checks: List[Dict[str, Any]] = []

            for entry in self.payloads:
                techniques = {
                    str(value).strip().lower()
                    for value in entry.get("techniques", [])
                    if str(value).strip()
                }
                if "error" in techniques:
                    legacy_error_checks.append(
                        {
                            "name": entry.get("name"),
                            "value": entry.get("value"),
                            "param_contexts": entry.get("param_contexts"),
                            "dialects": entry.get("dialects"),
                        }
                    )
                if "time" in techniques:
                    legacy_time_checks.append(
                        {
                            "name": entry.get("name"),
                            "delay": entry.get("value"),
                            "control": None,
                            "param_contexts": entry.get("param_contexts"),
                            "dialects": entry.get("dialects"),
                        }
                    )

            if legacy_error_checks:
                self.error_checks = legacy_error_checks
            if legacy_time_checks:
                self.time_checks = legacy_time_checks

        if self.boolean_payload_pairs:
            self.boolean_checks = list(self.boolean_payload_pairs)

        if self.boolean_true_payloads and self.boolean_false_payloads:
            self.boolean_checks = []
            for idx, (true_payload, false_payload) in enumerate(
                zip(self.boolean_true_payloads, self.boolean_false_payloads)
            ):
                self.boolean_checks.append(
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
                for pair in self.boolean_checks
                if str(pair.get("true", "")).strip()
            ]
        if self.boolean_false_payloads is None:
            self.boolean_false_payloads = [
                str(pair.get("false", ""))
                for pair in self.boolean_checks
                if str(pair.get("false", "")).strip()
            ]
        if self.boolean_payload_pairs is None:
            self.boolean_payload_pairs = list(self.boolean_checks)
        if self.payloads is None:
            self.payloads = []
            for check in self.error_checks:
                self.payloads.append(
                    {
                        "name": check.get("name"),
                        "value": check.get("value"),
                        "techniques": ["error"],
                        "param_contexts": check.get("param_contexts", ["unknown"]),
                        "dialects": check.get("dialects", ["any"]),
                    }
                )
            for check in self.time_checks:
                self.payloads.append(
                    {
                        "name": check.get("name"),
                        "value": check.get("delay"),
                        "techniques": ["time"],
                        "param_contexts": check.get("param_contexts", ["unknown"]),
                        "dialects": check.get("dialects", ["any"]),
                    }
                )


@dataclass
class ScannerConfig:
    target_url: str
    use_browser: bool = True
    request: Optional[RequestConfig] = None
    browser: Optional[BrowserConfig] = None
    crawler: Optional[CrawlerConfig] = None
    sqli: Optional[SQLiConfig] = None

    def __post_init__(self):
        if self.request is None:
            self.request = RequestConfig()
        if self.browser is None:
            self.browser = BrowserConfig()
        if self.crawler is None:
            self.crawler = CrawlerConfig()
        if self.sqli is None:
            self.sqli = SQLiConfig()
