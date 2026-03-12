from collections import Counter
from difflib import SequenceMatcher
from statistics import median
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Set

from config import ScannerConfig
from models import Page, SQLiFinding
from scanners.sqli_contexts import derive_param_context, detect_sql_error_markers
from scanners.sqli_payloads import (
    normalize_boolean_pairs,
    normalize_payloads,
    select_boolean_pairs_by_context,
    select_payloads_by_context,
)
from state import ScannerState
from transport import Transport


TIME_KEYWORDS = ("sleep", "benchmark", "waitfor delay", "pg_sleep")


class SQLiScanner:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self._seen: set[tuple[str, str, str, str, str]] = set()

        self.payload_catalog = normalize_payloads(self.config.sqli.payloads or [])
        pair_source = self._resolve_boolean_pair_source()
        self.boolean_pair_catalog = normalize_boolean_pairs(pair_source)

    def scan_pages(self, pages: List[Page]) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []
        self._seen.clear()
        for page in pages:
            findings.extend(self.scan_url_params(page))
            findings.extend(self.scan_forms(page))
        return findings

    def scan_url_params(self, page: Page) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)

        for param in params:
            if self.state.is_param_tested(page.url, "GET", param, scope="sqli"):
                continue
            self.state.mark_param_tested(page.url, "GET", param, scope="sqli")

            baseline_params = params.copy()
            baseline_params[param] = "1"
            baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_params, doseq=True)))
            baseline_resp = self._collect_baseline(lambda: self.transport.request("GET", baseline_url))
            if not baseline_resp:
                continue

            context = self._derive_url_context(
                parsed=parsed,
                params=params,
                param=param,
                baseline_resp=baseline_resp,
            )

            payload_candidates = self._select_payloads_for_context(context)
            for payload in payload_candidates:
                value = str(payload.get("value", "")).strip()
                if not value:
                    continue

                new_params = params.copy()
                new_params[param] = value
                test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                resp = self.transport.request("GET", test_url)
                if resp.status_code == 0:
                    continue

                finding = self.analyze_response(
                    baseline_text=baseline_resp.text,
                    baseline_status=baseline_resp.status_code,
                    baseline_time=baseline_resp.elapsed,
                    response_text=resp.text,
                    response_status=resp.status_code,
                    response_time=resp.elapsed,
                    url=test_url,
                    method="GET",
                    param=param,
                    payload=value,
                    payload_techniques=set(payload.get("techniques", [])),
                )
                if finding:
                    findings.append(finding)

            if self.config.sqli.boolean_enabled:
                boolean_pairs = self._select_boolean_pairs_for_context(context)
                findings.extend(
                    self.run_boolean_checks_url(
                        parsed=parsed,
                        params=params,
                        param=param,
                        baseline_resp=baseline_resp,
                        pair_catalog=boolean_pairs,
                    )
                )
        return findings

    def scan_forms(self, page: Page) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for form in page.forms:
            action = form.absolute_action()
            method = form.method.upper()
            signature = self.form_signature(form.inputs)

            if self.state.is_form_tested(action, method, signature, scope="sqli"):
                continue
            self.state.mark_form_tested(action, method, signature, scope="sqli")

            for input_field in form.inputs:
                if not input_field.name:
                    continue

                baseline_data = {f.name: "1" for f in form.inputs if f.name}
                baseline_resp = self._collect_baseline(
                    lambda: self._send_form(method, action, baseline_data)
                )
                if not baseline_resp:
                    continue

                context = self._derive_form_context(
                    method=method,
                    action=action,
                    target_field=input_field.name,
                    baseline_data=baseline_data,
                    baseline_resp=baseline_resp,
                )

                payload_candidates = self._select_payloads_for_context(context)
                for payload in payload_candidates:
                    value = str(payload.get("value", "")).strip()
                    if not value:
                        continue

                    data = {f.name: "1" for f in form.inputs if f.name}
                    data[input_field.name] = value
                    resp = self._send_form(method, action, data)
                    if resp.status_code == 0:
                        continue

                    finding = self.analyze_response(
                        baseline_text=baseline_resp.text,
                        baseline_status=baseline_resp.status_code,
                        baseline_time=baseline_resp.elapsed,
                        response_text=resp.text,
                        response_status=resp.status_code,
                        response_time=resp.elapsed,
                        url=action,
                        method=method,
                        param=input_field.name,
                        payload=value,
                        payload_techniques=set(payload.get("techniques", [])),
                    )
                    if finding:
                        findings.append(finding)

                if self.config.sqli.boolean_enabled:
                    boolean_pairs = self._select_boolean_pairs_for_context(context)
                    findings.extend(
                        self.run_boolean_checks_form(
                            method=method,
                            action=action,
                            target_field=input_field.name,
                            baseline_data=baseline_data,
                            baseline_resp=baseline_resp,
                            pair_catalog=boolean_pairs,
                        )
                    )
        return findings

    def run_boolean_checks_url(
        self,
        parsed,
        params,
        param: str,
        baseline_resp,
        pair_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for pair in pair_catalog:
            true_payload = str(pair.get("true", "")).strip()
            false_payload = str(pair.get("false", "")).strip()
            if not true_payload or not false_payload:
                continue

            true_params = params.copy()
            true_params[param] = true_payload
            true_url = urlunparse(parsed._replace(query=urlencode(true_params, doseq=True)))
            true_resp = self.transport.request("GET", true_url)

            false_params = params.copy()
            false_params[param] = false_payload
            false_url = urlunparse(parsed._replace(query=urlencode(false_params, doseq=True)))
            false_resp = self.transport.request("GET", false_url)

            if true_resp.status_code == 0 or false_resp.status_code == 0:
                continue

            finding = self.detect_boolean_finding(
                baseline_text=baseline_resp.text,
                baseline_status=baseline_resp.status_code,
                true_text=true_resp.text,
                true_status=true_resp.status_code,
                false_text=false_resp.text,
                false_status=false_resp.status_code,
                url=true_url,
                method="GET",
                param=param,
                true_payload=true_payload,
                false_payload=false_payload,
                response_time=max(true_resp.elapsed, false_resp.elapsed),
            )
            if finding:
                findings.append(finding)

        return findings

    def run_boolean_checks_form(
        self,
        method: str,
        action: str,
        target_field: str,
        baseline_data: dict,
        baseline_resp,
        pair_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for pair in pair_catalog:
            true_payload = str(pair.get("true", "")).strip()
            false_payload = str(pair.get("false", "")).strip()
            if not true_payload or not false_payload:
                continue

            true_data = dict(baseline_data)
            true_data[target_field] = true_payload
            true_resp = self._send_form(method, action, true_data)

            false_data = dict(baseline_data)
            false_data[target_field] = false_payload
            false_resp = self._send_form(method, action, false_data)

            if true_resp.status_code == 0 or false_resp.status_code == 0:
                continue

            finding = self.detect_boolean_finding(
                baseline_text=baseline_resp.text,
                baseline_status=baseline_resp.status_code,
                true_text=true_resp.text,
                true_status=true_resp.status_code,
                false_text=false_resp.text,
                false_status=false_resp.status_code,
                url=action,
                method=method,
                param=target_field,
                true_payload=true_payload,
                false_payload=false_payload,
                response_time=max(true_resp.elapsed, false_resp.elapsed),
            )
            if finding:
                findings.append(finding)

        return findings

    def analyze_response(
        self,
        baseline_text: str,
        baseline_status: int,
        baseline_time: float,
        response_text: str,
        response_status: int,
        response_time: float,
        url: str,
        method: str,
        param: str,
        payload: str,
        payload_techniques: Set[str] | None = None,
    ) -> SQLiFinding | None:
        if self._reject_unstable_statuses(baseline_status, response_status):
            return None

        allowed_techniques = set(payload_techniques or {"error", "time", "boolean"})
        marker_info = detect_sql_error_markers(response_text)

        if marker_info["has_sql_error"] and "error" in allowed_techniques:
            marker_str = ", ".join(sorted(marker_info["markers"])) or "generic SQL error marker"
            return self._make_unique_finding(
                SQLiFinding(
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    technique="error",
                    response_time=response_time,
                    evidence=f"Detected SQL error marker(s): {marker_str}",
                    confidence="high",
                )
            )

        delta = response_time - baseline_time
        threshold = max(1.0, self.config.sqli.time_based_delay - 1.0)
        payload_low = payload.lower()
        is_time_payload = any(keyword in payload_low for keyword in TIME_KEYWORDS)
        if (
            "time" in allowed_techniques
            and is_time_payload
            and delta >= threshold
        ):
            return self._make_unique_finding(
                SQLiFinding(
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    technique="time",
                    response_time=response_time,
                    evidence=(
                        f"Baseline={baseline_time:.2f}s ({baseline_status}), "
                        f"injected={response_time:.2f}s ({response_status}), delta={delta:.2f}s"
                    ),
                    confidence="medium",
                )
            )

        return None

    def detect_boolean_finding(
        self,
        baseline_text: str,
        baseline_status: int,
        true_text: str,
        true_status: int,
        false_text: str,
        false_status: int,
        url: str,
        method: str,
        param: str,
        true_payload: str,
        false_payload: str,
        response_time: float,
    ) -> SQLiFinding | None:
        if self._reject_unstable_statuses(baseline_status, true_status, false_status):
            return None

        sim_true = self.similarity(baseline_text, true_text)
        sim_false = self.similarity(baseline_text, false_text)
        gap = abs(sim_true - sim_false)

        status_diverged = (
            (true_status != false_status)
            or (true_status != baseline_status and false_status == baseline_status)
        )
        enough_gap = gap >= self.config.sqli.boolean_min_gap
        if not status_diverged and not enough_gap:
            return None

        likely_true = sim_true > sim_false
        confidence = (
            "high"
            if gap >= (self.config.sqli.boolean_min_gap * 1.8)
            else "medium"
        )
        payload = true_payload if likely_true else false_payload
        evidence = (
            f"similarity(baseline,true)={sim_true:.3f}, "
            f"similarity(baseline,false)={sim_false:.3f}, gap={gap:.3f}, "
            f"statuses baseline/true/false={baseline_status}/{true_status}/{false_status}"
        )

        return self._make_unique_finding(
            SQLiFinding(
                url=url,
                method=method,
                param=param,
                payload=payload,
                technique="boolean",
                response_time=response_time,
                evidence=evidence,
                confidence=confidence,
            )
        )

    @staticmethod
    def similarity(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a[:20000], b[:20000]).ratio()

    def _send_form(self, method: str, action: str, data: dict):
        if method == "GET":
            return self.transport.request(method, action, params=data)
        return self.transport.request(method, action, data=data)

    def _make_unique_finding(self, finding: SQLiFinding) -> SQLiFinding | None:
        key = (
            finding.url,
            finding.method,
            finding.param,
            finding.payload,
            finding.technique,
        )
        if key in self._seen:
            return None
        self._seen.add(key)
        return finding

    def _collect_baseline(self, requester):
        attempts = max(1, self.config.sqli.baseline_samples)
        responses = []
        for _ in range(attempts):
            resp = requester()
            if resp.status_code != 0:
                responses.append(resp)
        if not responses:
            return None

        statuses = [r.status_code for r in responses]
        status_counter = Counter(statuses)
        dominant_status, count = status_counter.most_common(1)[0]
        if attempts > 1 and count < 2:
            return None

        selected = [r for r in responses if r.status_code == dominant_status]
        if not selected:
            return None

        if self._reject_unstable_statuses(dominant_status):
            return None

        baseline = selected[0]
        baseline.elapsed = float(median([r.elapsed for r in selected]))
        return baseline

    def _reject_unstable_statuses(self, *statuses: int) -> bool:
        if not self.config.sqli.ignore_server_errors_for_heuristics:
            return False
        return any(status >= 500 for status in statuses if status)

    def _derive_url_context(self, parsed, params, param: str, baseline_resp) -> Dict[str, Any]:
        quote_params = params.copy()
        quote_params[param] = "'"
        quote_url = urlunparse(parsed._replace(query=urlencode(quote_params, doseq=True)))
        quote_resp = self.transport.request("GET", quote_url)

        numeric_params = params.copy()
        numeric_params[param] = "1-1"
        numeric_url = urlunparse(parsed._replace(query=urlencode(numeric_params, doseq=True)))
        numeric_resp = self.transport.request("GET", numeric_url)

        quote_status = quote_resp.status_code or baseline_resp.status_code
        numeric_status = numeric_resp.status_code or baseline_resp.status_code
        quote_text = quote_resp.text if quote_resp.status_code else baseline_resp.text
        numeric_text = numeric_resp.text if numeric_resp.status_code else baseline_resp.text

        return derive_param_context(
            baseline_status=baseline_resp.status_code,
            baseline_text=baseline_resp.text,
            quote_status=quote_status,
            quote_text=quote_text,
            numeric_status=numeric_status,
            numeric_text=numeric_text,
        )

    def _derive_form_context(
        self,
        method: str,
        action: str,
        target_field: str,
        baseline_data: Dict[str, Any],
        baseline_resp,
    ) -> Dict[str, Any]:
        quote_data = dict(baseline_data)
        quote_data[target_field] = "'"
        quote_resp = self._send_form(method, action, quote_data)

        numeric_data = dict(baseline_data)
        numeric_data[target_field] = "1-1"
        numeric_resp = self._send_form(method, action, numeric_data)

        quote_status = quote_resp.status_code or baseline_resp.status_code
        numeric_status = numeric_resp.status_code or baseline_resp.status_code
        quote_text = quote_resp.text if quote_resp.status_code else baseline_resp.text
        numeric_text = numeric_resp.text if numeric_resp.status_code else baseline_resp.text

        return derive_param_context(
            baseline_status=baseline_resp.status_code,
            baseline_text=baseline_resp.text,
            quote_status=quote_status,
            quote_text=quote_text,
            numeric_status=numeric_status,
            numeric_text=numeric_text,
        )

    def _select_payloads_for_context(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = select_payloads_by_context(
            payload_catalog=self.payload_catalog,
            techniques=set(context.get("techniques", {"error", "boolean", "time"})),
            param_context=str(context.get("param_context", "unknown")),
            dialects=set(context.get("dialects", {"any"})),
        )
        return candidates or self.payload_catalog

    def _select_boolean_pairs_for_context(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = select_boolean_pairs_by_context(
            pair_catalog=self.boolean_pair_catalog,
            param_context=str(context.get("param_context", "unknown")),
            dialects=set(context.get("dialects", {"any"})),
        )
        return candidates or self.boolean_pair_catalog

    def _resolve_boolean_pair_source(self) -> List[Dict[str, Any] | tuple[str, str]]:
        if self.config.sqli.boolean_payload_pairs:
            return list(self.config.sqli.boolean_payload_pairs)

        true_payloads = list(self.config.sqli.boolean_true_payloads or [])
        false_payloads = list(self.config.sqli.boolean_false_payloads or [])
        return list(zip(true_payloads, false_payloads))

    @staticmethod
    def form_signature(inputs) -> str:
        names = sorted(field.name for field in inputs if field.name)
        return "|".join(names)
