import html
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Set, Tuple

from models import Page, ReflectedContext, ReflectionLocation, XSSFinding
from config import ScannerConfig
from transport import Transport
from state import ScannerState
from scanners.xss_contexts import detect_locations, derive_contexts
from scanners.xss_payloads import (
    expand_context_aliases,
    normalize_payloads,
    select_payloads_by_context,
)


class XSSScanner:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self.payload_catalog = normalize_payloads(self.config.xss.payloads or [])
        self._seen_finding_keys: set[Tuple[str, str, str, str]] = set()

    def scan_pages(self, pages: List[Page]) -> List[XSSFinding]:
        findings: List[XSSFinding] = []
        self._seen_finding_keys.clear()

        for page in pages:
            findings.extend(self.scan_url_params(page))
            findings.extend(self.scan_forms(page))

        return findings

    def scan_url_params(self, page: Page) -> List[XSSFinding]:
        findings: List[XSSFinding] = []
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)

        for param in params:
            if self.state.is_param_tested(page.url, "GET", param, scope="xss"):
                continue
            self.state.mark_param_tested(page.url, "GET", param, scope="xss")

            marker = self._make_probe_marker(param)
            probe_params = params.copy()
            probe_params[param] = marker
            probe_url = urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))
            probe_response = self.transport.request("GET", probe_url)

            if probe_response.status_code == 0 or not self._is_marker_reflected(probe_response.text, marker):
                continue

            probe_locations = detect_locations(marker, probe_response.text)
            probe_contexts = derive_contexts(probe_response.text, marker, probe_locations)
            payload_candidates = self._select_payloads(probe_contexts)
            if not payload_candidates:
                continue

            for payload in payload_candidates:
                attack_params = params.copy()
                attack_params[param] = payload["value"]
                attack_url = urlunparse(parsed._replace(query=urlencode(attack_params, doseq=True)))
                attack_response = self.transport.request("GET", attack_url)
                if attack_response.status_code == 0:
                    continue

                finding = self.analyze_response(
                    response_text=attack_response.text,
                    status_code=attack_response.status_code,
                    url=attack_url,
                    method="GET",
                    param=param,
                    payload=payload,
                    probe_contexts=probe_contexts,
                )
                if finding:
                    findings.append(finding)

        return findings

    def scan_forms(self, page: Page) -> List[XSSFinding]:
        findings: List[XSSFinding] = []

        for form in page.forms:
            action = form.absolute_action()
            method = form.method.upper()
            signature = self.form_signature(form.inputs)

            if self.state.is_form_tested(action, method, signature, scope="xss"):
                continue
            self.state.mark_form_tested(action, method, signature, scope="xss")

            for input_field in form.inputs:
                if not input_field.name:
                    continue

                marker = self._make_probe_marker(input_field.name)
                probe_data = {
                    field.name: (marker if field.name == input_field.name else "test")
                    for field in form.inputs
                    if field.name
                }

                probe_response = self._send_form(method, action, probe_data)
                if probe_response.status_code == 0 or not self._is_marker_reflected(probe_response.text, marker):
                    continue

                probe_locations = detect_locations(marker, probe_response.text)
                probe_contexts = derive_contexts(probe_response.text, marker, probe_locations)
                payload_candidates = self._select_payloads(probe_contexts)
                if not payload_candidates:
                    continue

                for payload in payload_candidates:
                    attack_data = {
                        field.name: (payload["value"] if field.name == input_field.name else "test")
                        for field in form.inputs
                        if field.name
                    }
                    attack_response = self._send_form(method, action, attack_data)
                    if attack_response.status_code == 0:
                        continue

                    finding = self.analyze_response(
                        response_text=attack_response.text,
                        status_code=attack_response.status_code,
                        url=action,
                        method=method,
                        param=input_field.name,
                        payload=payload,
                        probe_contexts=probe_contexts,
                        request_params=attack_data if method == "GET" else None,
                        request_data=attack_data if method != "GET" else None,
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def analyze_response(
        self,
        response_text: str,
        status_code: int,
        url: str,
        method: str,
        param: str,
        payload: Dict[str, Any],
        probe_contexts: List[ReflectedContext],
        request_params: Dict[str, Any] | None = None,
        request_data: Dict[str, Any] | None = None,
    ) -> XSSFinding | None:
        payload_value = str(payload["value"])
        reflection_mode = self.reflection_mode(payload_value, response_text)
        if reflection_mode == "none":
            return None
        if reflection_mode == "html_escaped" and not self.config.xss.include_informational:
            return None

        reflection_locations = detect_locations(payload_value, response_text)
        detected_contexts = derive_contexts(response_text, payload_value, reflection_locations)
        confidence = self.calculate_confidence(
            reflection_mode=reflection_mode,
            reflection_locations=reflection_locations,
            probe_contexts=probe_contexts,
            attack_contexts=detected_contexts,
            payload_contexts=set(payload.get("contexts", [])),
        )

        finding = XSSFinding(
            url=url,
            method=method,
            param=param,
            payload=payload_value,
            payload_name=str(payload.get("name", payload_value[:40])),
            reflected_as=reflection_mode,
            reflection_mode=reflection_mode,
            confidence=confidence,
            status_code=status_code,
            reflection_locations=reflection_locations,
            detected_contexts=detected_contexts,
            evidence_snippet=self.extract_snippet(payload_value, response_text),
        )

        finding = self.apply_dom_confirmation_if_enabled(
            finding=finding,
            method=method,
            url=url,
            params=request_params,
            data=request_data,
        )

        key = (finding.url, finding.method, finding.param, finding.payload)
        if key in self._seen_finding_keys:
            return None
        self._seen_finding_keys.add(key)
        return finding

    def calculate_confidence(
        self,
        reflection_mode: str,
        reflection_locations: List[ReflectionLocation],
        probe_contexts: List[ReflectedContext],
        attack_contexts: List[ReflectedContext],
        payload_contexts: Set[str],
    ) -> str:
        if reflection_mode == "html_escaped":
            return "info"
        if reflection_mode != "raw":
            return "low"

        score = 0
        probe_set = expand_context_aliases({ctx.context for ctx in probe_contexts})
        attack_set = expand_context_aliases({ctx.context for ctx in attack_contexts})
        payload_set = expand_context_aliases(set(payload_contexts))

        if probe_set and attack_set and probe_set.intersection(attack_set):
            score += 1
        if payload_set and attack_set and payload_set.intersection(attack_set):
            score += 1
        if any(loc.location_type in {"script", "event"} for loc in reflection_locations):
            score += 1

        if score >= 3:
            return "high"
        if score >= 1:
            return "medium"
        return "low"

    def apply_dom_confirmation_if_enabled(
        self,
        finding: XSSFinding,
        method: str,
        url: str,
        params: Dict[str, Any] | None,
        data: Dict[str, Any] | None,
    ) -> XSSFinding:
        if not self.config.xss.dom_confirmation_enabled:
            return finding
        if self.config.xss.dom_confirmation_only_raw and finding.reflection_mode != "raw":
            return finding
        if not self.confirm_dom_execution(method, url, params, data):
            return finding

        snippet = finding.evidence_snippet
        if "[DOM confirmed]" not in snippet:
            snippet = f"[DOM confirmed] {snippet}".strip()

        return XSSFinding(
            url=finding.url,
            method=finding.method,
            param=finding.param,
            payload=finding.payload,
            payload_name=finding.payload_name,
            reflected_as=finding.reflected_as,
            reflection_mode=finding.reflection_mode,
            confidence="high",
            status_code=finding.status_code,
            reflection_locations=finding.reflection_locations,
            detected_contexts=finding.detected_contexts,
            evidence_snippet=snippet,
        )

    def confirm_dom_execution(
        self,
        method: str,
        url: str,
        params: Dict[str, Any] | None,
        data: Dict[str, Any] | None,
    ) -> bool:
        if not self.transport.browser:
            return False

        page = self.transport.browser.page
        dialog_hit = {"value": False}

        def on_dialog(dialog):
            dialog_hit["value"] = True
            dialog.dismiss()

        try:
            self.transport.browser.reset_xss_marker()
            page.on("dialog", on_dialog)
            self.transport.request(
                method=method,
                url=url,
                params=params,
                data=data,
                use_browser=True,
            )
            page.wait_for_timeout(self.config.xss.dom_confirmation_wait_ms)
            return bool(dialog_hit["value"] or self.transport.browser.read_xss_marker())
        except Exception:
            return False
        finally:
            try:
                page.remove_listener("dialog", on_dialog)
            except Exception:
                pass

    @staticmethod
    def reflection_mode(payload: str, response_text: str) -> str:
        escaped_html = html.escape(payload)
        if payload in response_text:
            return "raw"
        if escaped_html in response_text:
            return "html_escaped"
        if "\\x3c" in response_text.lower() and "<" in payload:
            return "js_escaped"
        return "none"

    @staticmethod
    def extract_snippet(payload: str, response_text: str) -> str:
        marker = payload if payload in response_text else html.escape(payload)
        index = response_text.find(marker)
        if index == -1:
            return ""
        start = max(index - 80, 0)
        end = min(index + len(marker) + 80, len(response_text))
        return response_text[start:end].replace("\n", " ").replace("\r", " ")

    def _select_payloads(self, contexts: List[ReflectedContext]) -> List[Dict[str, Any]]:
        return select_payloads_by_context(
            payload_catalog=self.payload_catalog,
            detected_contexts={ctx.context for ctx in contexts},
        )

    @staticmethod
    def _make_probe_marker(param_name: str) -> str:
        safe_name = "".join(ch for ch in param_name if ch.isalnum() or ch == "_")[:16] or "p"
        return f"XSSCTX_{safe_name}_{secrets.token_hex(3)}"

    @staticmethod
    def _is_marker_reflected(response_text: str, marker: str) -> bool:
        return marker in response_text or html.escape(marker) in response_text

    def _send_form(self, method: str, action: str, data: Dict[str, Any]):
        if method == "GET":
            return self.transport.request(method, action, params=data)
        return self.transport.request(method, action, data=data)

    @staticmethod
    def form_signature(inputs) -> str:
        names = sorted(field.name for field in inputs if field.name)
        return "|".join(names)
