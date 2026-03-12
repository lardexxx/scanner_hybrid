from typing import Dict, List

from config import ScannerConfig
from models import CSRFFinding, Form, Page
from scanners.csrf_active import probe_missing_token, probe_tampered_token
from scanners.csrf_checks import detect_samesite_issue
from scanners.csrf_contexts import build_form_data, classify_form
from state import ScannerState
from transport import Transport


class CSRFScanner:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self._seen: set[tuple[str, str, bool, bool]] = set()

    def scan_pages(self, pages: List[Page]) -> List[CSRFFinding]:
        findings: List[CSRFFinding] = []
        self._seen.clear()
        for page in pages:
            for form in page.forms:
                findings.extend(self.scan_form(form))
        return findings

    def scan_form(self, form: Form) -> List[CSRFFinding]:
        findings: List[CSRFFinding] = []
        context = classify_form(form)

        method = str(context["method"])
        action = str(context["action"])
        is_state_changing = bool(context["is_state_changing"])
        has_token = bool(context["has_token"])
        token_fields = list(context["token_fields"])
        is_auth_or_search = bool(context["is_auth_like"]) or bool(context["is_search_like"])

        if not is_state_changing:
            return findings

        samesite_issue = self._detect_samesite_issue(action)
        missing_token = not has_token

        if missing_token:
            if not self.config.csrf.require_token:
                return findings
            if is_auth_or_search and not self.config.csrf.include_auth_forms:
                return findings

            findings.append(
                CSRFFinding(
                    url=form.source_url,
                    form_action=action,
                    method=method,
                    missing_token=True,
                    samesite_issue=samesite_issue,
                    confidence=self.confidence(
                        missing_token=True,
                        bypass_possible=False,
                        samesite_issue=samesite_issue,
                        is_auth_or_search=is_auth_or_search,
                    ),
                )
            )
            return self._dedup(findings)

        bypass_possible = False
        if bool(getattr(self.config.csrf, "active_checks_enabled", True)):
            baseline_data = build_form_data(form, remove_fields=None, override_fields=None)
            min_len_ratio = float(getattr(self.config.csrf, "min_length_ratio", 0.88))
            min_similarity = float(getattr(self.config.csrf, "min_response_similarity", 0.90))

            missing_token_probe = probe_missing_token(
                method=method,
                action=action,
                baseline_data=baseline_data,
                token_fields=token_fields,
                sender=self._send,
                min_len_ratio=min_len_ratio,
                min_similarity=min_similarity,
            )
            tampered_probe = probe_tampered_token(
                method=method,
                action=action,
                baseline_data=baseline_data,
                token_fields=token_fields,
                sender=self._send,
                min_len_ratio=min_len_ratio,
                min_similarity=min_similarity,
            )
            bypass_possible = bool(missing_token_probe["bypass_possible"]) or bool(
                tampered_probe["bypass_possible"]
            )

        if bypass_possible:
            findings.append(
                CSRFFinding(
                    url=form.source_url,
                    form_action=action,
                    method=method,
                    missing_token=False,
                    samesite_issue=samesite_issue,
                    confidence=self.confidence(
                        missing_token=False,
                        bypass_possible=True,
                        samesite_issue=samesite_issue,
                        is_auth_or_search=is_auth_or_search,
                    ),
                )
            )
        elif samesite_issue:
            findings.append(
                CSRFFinding(
                    url=form.source_url,
                    form_action=action,
                    method=method,
                    missing_token=False,
                    samesite_issue=True,
                    confidence="low",
                )
            )

        return self._dedup(findings)

    def confidence(
        self,
        missing_token: bool,
        bypass_possible: bool,
        samesite_issue: bool,
        is_auth_or_search: bool,
    ) -> str:
        if bypass_possible:
            return "high"
        if missing_token and is_auth_or_search:
            return "low"
        if missing_token and samesite_issue:
            return "medium"
        if missing_token:
            return "medium"
        if samesite_issue:
            return "low"
        return "low"

    def _detect_samesite_issue(self, action: str) -> bool:
        if not self.config.csrf.check_samesite:
            return False

        resp = self.transport.request("GET", action)
        if resp.status_code == 0:
            return False
        return detect_samesite_issue(resp.headers)

    def _dedup(self, findings: List[CSRFFinding]) -> List[CSRFFinding]:
        unique: List[CSRFFinding] = []
        for finding in findings:
            key = (
                finding.form_action,
                finding.method,
                finding.missing_token,
                finding.samesite_issue,
            )
            if key in self._seen:
                continue
            self._seen.add(key)
            unique.append(finding)
        return unique

    def _send(self, method: str, action: str, data: Dict[str, str]):
        if method == "GET":
            return self.transport.request(method, action, params=data)
        return self.transport.request(method, action, data=data)
