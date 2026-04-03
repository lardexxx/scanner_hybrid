import copy
from collections import Counter
from difflib import SequenceMatcher
from statistics import median
from typing import Any, Dict, List, Optional, Set

from config import ScannerConfig
from form_extraction import build_form_data
from models import Form, InputPoint, ObservedRequest, Page, SQLiFinding
from scanners.sqli_contexts import detect_sql_error_hints, derive_param_context
from scanners.sqli_payloads import (
    normalize_boolean_checks,
    normalize_error_checks,
    normalize_time_checks,
    select_boolean_checks_by_context,
    select_error_checks_by_context,
    select_time_checks_by_context,
)
from setupe_urls import ScannerState
from transport import Response, Transport

# Сейчас sqli_scanner работает так (по этапам) в sqli_scanner.py:
# 1.
# В __init__ он поднимает и нормализует 3 каталога проверок:
# •
# error_check_catalog
# •
# boolean_check_catalog
# •
# time_check_catalog
# Источники берутся из config.py через функции из sqli_payloads.py.
# 2.
# В scan_pages() проходит по pages, и для каждой страницы строит индексы:
# •
# request_index из page.observed_requests
# •
# form_index из page.forms
# Потом идет по page.input_points и берет только query, form_field, json_field.
# 3.
# Перед сканом точки делает дедуп через state:
# •
# если параметр уже тестировался, пропускает;
# •
# иначе помечает как протестированный.
# 4.
# Для каждой точки вызывает scan_input_point():
# •
# query/json_field -> ветка _scan_request_point(...)
# •
# form_field -> ветка _scan_form_point(...)
# 5.
# Внутри ветки сначала собирает baseline (_collect_baseline):
# •
# делает baseline_samples запросов;
# •
# берет доминирующий status_code;
# •
# использует медиану времени.
# 6.
# Дальше делает precheck-контекст (_derive_*_context) через sqli_contexts.py:
# •
# пробует ' и 1-1;
# •
# получает param_context, candidate_dialects, blind_proof_allowed.
# 7.
# Запускает error checks:
# •
# выбирает подходящие проверки по контексту/диалекту;
# •
# каждую проверку гоняет error_trials раз;
# •
# успех только если в каждом trial появились новые SQL error hints относительно baseline;
# •
# тогда создает SQLiFinding с technique="error".
# 8.
# Если blind_proof_allowed и boolean_enabled, запускает boolean checks:
# •
# для пары true/false делает boolean_trials серий;
# •
# серия успешна, если:
# ◦
# нет 5xx;
# ◦
# gap(sim_true, sim_false) >= boolean_min_gap;
# ◦
# true ближе к baseline, чем false;
# •
# finding создается только если успешны все trials.
# 9.
# Там же запускает time checks:
# •
# для delay/control делает time_trials;
# •
# серия успешна, если нет 5xx и delay_time - reference_time >= max(1, time_based_delay - 1), где reference_time = max(baseline, control) (если control есть);
# •
# finding создается только при успехе всех trials.
# 10.
# Любой finding проходит _make_unique_finding():
# •
# ключ: (url, method, param, payload, technique);
# •
# дубликаты не возвращаются.
# 11.
# На выходе scan_pages() возвращает только доказанные находки (proof_status="proven"), с полями trials_run и successful_trials в models.py.
class SQLiScanner:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self._seen = set()

        self.error_check_catalog = normalize_error_checks(self.config.sqli.error_checks or [])
        self.boolean_check_catalog = normalize_boolean_checks(
            self._resolve_boolean_check_source()
        )
        self.time_check_catalog = normalize_time_checks(self.config.sqli.time_checks or [])

    def scan_pages(self, pages: List[Page]) -> List[SQLiFinding]:  #список найденных sqlifindings
        findings: List[SQLiFinding] = []
        self._seen.clear()

        for page in pages:
            request_index = self._index_requests(page.observed_requests or [])
            form_index = self._index_forms(page.forms or [])

            for point in page.input_points or []:
                if point.kind not in {"query", "form_field", "json_field"}:
                    continue

                tracking_key = f"{point.kind}:{point.locator}:{point.source_kind}"
                if self.state.is_param_tested(
                    point.request_url, point.method, tracking_key, scope="sqli"
                ):
                    continue
                self.state.mark_param_tested(
                    point.request_url, point.method, tracking_key, scope="sqli"
                )

                findings.extend(
                    self.scan_input_point(
                        point=point,
                        request_index=request_index,
                        form_index=form_index,
                    )
                )

        return findings

    def scan_input_point(
        self,
        point: InputPoint,
        request_index: Dict[tuple[str, str, str], ObservedRequest],
        form_index: Dict[tuple[str, str, str], Form],
    ) -> List[SQLiFinding]:
        if point.kind in {"query", "json_field"}:
            request = request_index.get((point.request_url, point.method.upper(), point.source_kind))
            if request is None:
                return []
            return self._scan_request_point(point, request)

        if point.kind == "form_field":
            form = form_index.get((point.request_url, point.method.upper(), point.locator))
            if form is None:
                return []
            return self._scan_form_point(point, form)

        return []

    def _scan_request_point(self, point: InputPoint, request: ObservedRequest) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []
        baseline_resp = self._collect_baseline(
            lambda: self._send_request_variant(request, point, point.original_value)
        )
        if not baseline_resp:
            return findings

        context = self._derive_request_context(point, request, baseline_resp)
        param_context = str(context.get("param_context", "unknown"))
        candidate_dialects = set(context.get("candidate_dialects", {"any"}))

        error_checks = select_error_checks_by_context(
            check_catalog=self.error_check_catalog,
            param_context=param_context,
            candidate_dialects=candidate_dialects,
        )
        findings.extend(self._run_error_request_checks(point, request, baseline_resp, error_checks))

        if self.config.sqli.boolean_enabled and bool(context.get("blind_proof_allowed", False)):
            boolean_checks = select_boolean_checks_by_context(
                check_catalog=self.boolean_check_catalog,
                param_context=param_context,
                candidate_dialects=candidate_dialects,
            )
            findings.extend(
                self._run_boolean_request_checks(point, request, baseline_resp, boolean_checks)
            )

            time_checks = select_time_checks_by_context(
                check_catalog=self.time_check_catalog,
                param_context=param_context,
                candidate_dialects=candidate_dialects,
            )
            findings.extend(self._run_time_request_checks(point, request, baseline_resp, time_checks))

        return findings

    def _scan_form_point(self, point: InputPoint, form: Form) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []
        baseline_resp = self._collect_baseline(
            lambda: self._send_form_variant(form, point, point.original_value)
        )
        if not baseline_resp:
            return findings

        context = self._derive_form_context(point, form, baseline_resp)
        param_context = str(context.get("param_context", "unknown"))
        candidate_dialects = set(context.get("candidate_dialects", {"any"}))

        error_checks = select_error_checks_by_context(
            check_catalog=self.error_check_catalog,
            param_context=param_context,
            candidate_dialects=candidate_dialects,
        )
        findings.extend(self._run_error_form_checks(point, form, baseline_resp, error_checks))

        if self.config.sqli.boolean_enabled and bool(context.get("blind_proof_allowed", False)):
            boolean_checks = select_boolean_checks_by_context(
                check_catalog=self.boolean_check_catalog,
                param_context=param_context,
                candidate_dialects=candidate_dialects,
            )
            findings.extend(
                self._run_boolean_form_checks(point, form, baseline_resp, boolean_checks)
            )

            time_checks = select_time_checks_by_context(
                check_catalog=self.time_check_catalog,
                param_context=param_context,
                candidate_dialects=candidate_dialects,
            )
            findings.extend(self._run_time_form_checks(point, form, baseline_resp, time_checks))

        return findings

    def _run_error_request_checks(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            payload_value = str(check.get("value", "")).strip()
            if not payload_value:
                continue

            finding = self._run_error_request_check(point, request, baseline_resp, payload_value)
            if finding:
                findings.append(finding)

        return findings

    def _run_error_form_checks(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            payload_value = str(check.get("value", "")).strip()
            if not payload_value:
                continue

            finding = self._run_error_form_check(point, form, baseline_resp, payload_value)
            if finding:
                findings.append(finding)

        return findings

    def analyze_error_response(
        self,
        baseline_text: str,
        response_text: str,
        url: str,
        method: str,
        param: str,
        payload: str,
        response_time: float,
        trials_run: int = 1,
        successful_trials: int = 1,
    ) -> SQLiFinding | None:
        baseline_hints = detect_sql_error_hints(baseline_text)
        response_hints = detect_sql_error_hints(response_text)

        new_markers = set(response_hints["matched_markers"]) - set(baseline_hints["matched_markers"])
        if not response_hints["has_sql_error_hint"] or not new_markers:
            return None

        marker_str = ", ".join(sorted(new_markers))
        return self._make_unique_finding(
            SQLiFinding(
                url=url,
                method=method,
                param=param,
                payload=payload,
                technique="error",
                response_time=response_time,
                evidence=f"Новые SQL error hints: {marker_str}",
                confidence="high",
                proof_status="proven",
                trials_run=trials_run,
                successful_trials=successful_trials,
            )
        )

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
        trials_run: int = 1,
        successful_trials: int = 1,
    ) -> SQLiFinding | None:
        if not self._statuses_allow_blind(baseline_status, true_status, false_status):
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
        confidence = "high" if gap >= (self.config.sqli.boolean_min_gap * 1.8) else "medium"
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
                proof_status="proven",
                trials_run=trials_run,
                successful_trials=successful_trials,
            )
        )

    def detect_time_finding(
        self,
        baseline_resp: Response,
        delay_resp: Response,
        control_resp: Optional[Response],
        url: str,
        method: str,
        param: str,
        delay_payload: str,
        trials_run: int = 1,
        successful_trials: int = 1,
    ) -> SQLiFinding | None:
        compared_statuses = [baseline_resp.status_code, delay_resp.status_code]
        if control_resp is not None:
            compared_statuses.append(control_resp.status_code)
        if not self._statuses_allow_blind(*compared_statuses):
            return None

        threshold = max(1.0, float(self.config.sqli.time_based_delay) - 1.0)
        reference_time = baseline_resp.elapsed
        evidence_parts = [f"baseline={baseline_resp.elapsed:.2f}s"]

        if control_resp is not None:
            evidence_parts.append(f"control={control_resp.elapsed:.2f}s")
            reference_time = max(reference_time, control_resp.elapsed)

        delta = delay_resp.elapsed - reference_time
        if delta < threshold:
            return None

        evidence_parts.append(f"delay={delay_resp.elapsed:.2f}s")
        evidence_parts.append(f"delta={delta:.2f}s")
        confidence = "medium" if control_resp is None else "high"

        return self._make_unique_finding(
            SQLiFinding(
                url=url,
                method=method,
                param=param,
                payload=delay_payload,
                technique="time",
                response_time=delay_resp.elapsed,
                evidence=", ".join(evidence_parts),
                confidence=confidence,
                proof_status="proven",
                trials_run=trials_run,
                successful_trials=successful_trials,
            )
        )

    @staticmethod
    def similarity(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a[:20000], b[:20000]).ratio()

    def _run_boolean_request_checks(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            true_payload = str(check.get("true", "")).strip()
            false_payload = str(check.get("false", "")).strip()
            if not true_payload or not false_payload:
                continue

            finding = self._run_boolean_request_check(
                point=point,
                request=request,
                baseline_resp=baseline_resp,
                true_payload=true_payload,
                false_payload=false_payload,
            )
            if finding:
                findings.append(finding)

        return findings

    def _run_boolean_form_checks(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            true_payload = str(check.get("true", "")).strip()
            false_payload = str(check.get("false", "")).strip()
            if not true_payload or not false_payload:
                continue

            finding = self._run_boolean_form_check(
                point=point,
                form=form,
                baseline_resp=baseline_resp,
                true_payload=true_payload,
                false_payload=false_payload,
            )
            if finding:
                findings.append(finding)

        return findings

    def _run_time_request_checks(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            delay_payload = str(check.get("delay", "")).strip()
            control_payload = str(check.get("control", "")).strip()
            if not delay_payload:
                continue

            finding = self._run_time_request_check(
                point=point,
                request=request,
                baseline_resp=baseline_resp,
                delay_payload=delay_payload,
                control_payload=control_payload or None,
            )
            if finding:
                findings.append(finding)

        return findings

    def _run_time_form_checks(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        check_catalog: List[Dict[str, Any]],
    ) -> List[SQLiFinding]:
        findings: List[SQLiFinding] = []

        for check in check_catalog:
            delay_payload = str(check.get("delay", "")).strip()
            control_payload = str(check.get("control", "")).strip()
            if not delay_payload:
                continue

            finding = self._run_time_form_check(
                point=point,
                form=form,
                baseline_resp=baseline_resp,
                delay_payload=delay_payload,
                control_payload=control_payload or None,
            )
            if finding:
                findings.append(finding)

        return findings

    def _run_error_request_check(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        payload_value: str,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.error_trials))
        matched_markers: Set[str] = set()
        successful_trials = 0
        response_times: List[float] = []

        for _ in range(attempts):
            resp = self._send_request_variant(request, point, payload_value)
            if resp.status_code == 0:
                continue

            response_hints = detect_sql_error_hints(resp.text)
            baseline_hints = detect_sql_error_hints(baseline_resp.text)
            new_markers = set(response_hints["matched_markers"]) - set(
                baseline_hints["matched_markers"]
            )
            if not response_hints["has_sql_error_hint"] or not new_markers:
                continue

            successful_trials += 1
            response_times.append(resp.elapsed)
            matched_markers.update(new_markers)

        if successful_trials != attempts or not matched_markers:
            return None

        return self.analyze_error_response(
            baseline_text=baseline_resp.text,
            response_text=" ".join(sorted(matched_markers)),
            url=request.url,
            method=request.method,
            param=point.locator,
            payload=payload_value,
            response_time=float(median(response_times or [baseline_resp.elapsed])),
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _run_error_form_check(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        payload_value: str,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.error_trials))
        matched_markers: Set[str] = set()
        successful_trials = 0
        response_times: List[float] = []

        for _ in range(attempts):
            resp = self._send_form_variant(form, point, payload_value)
            if resp.status_code == 0:
                continue

            response_hints = detect_sql_error_hints(resp.text)
            baseline_hints = detect_sql_error_hints(baseline_resp.text)
            new_markers = set(response_hints["matched_markers"]) - set(
                baseline_hints["matched_markers"]
            )
            if not response_hints["has_sql_error_hint"] or not new_markers:
                continue

            successful_trials += 1
            response_times.append(resp.elapsed)
            matched_markers.update(new_markers)

        if successful_trials != attempts or not matched_markers:
            return None

        return self.analyze_error_response(
            baseline_text=baseline_resp.text,
            response_text=" ".join(sorted(matched_markers)),
            url=form.absolute_action(),
            method=form.method.upper(),
            param=point.locator,
            payload=payload_value,
            response_time=float(median(response_times or [baseline_resp.elapsed])),
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _run_boolean_request_check(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        true_payload: str,
        false_payload: str,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.boolean_trials))
        successful_trials = 0
        trial_records: List[tuple[Response, Response]] = []

        for _ in range(attempts):
            true_resp = self._send_request_variant(request, point, true_payload)
            false_resp = self._send_request_variant(request, point, false_payload)
            if true_resp.status_code == 0 or false_resp.status_code == 0:
                continue

            if self._boolean_trial_succeeded(baseline_resp, true_resp, false_resp):
                successful_trials += 1
                trial_records.append((true_resp, false_resp))

        if successful_trials != attempts or not trial_records:
            return None

        true_resp, false_resp = trial_records[-1]
        return self.detect_boolean_finding(
            baseline_text=baseline_resp.text,
            baseline_status=baseline_resp.status_code,
            true_text=true_resp.text,
            true_status=true_resp.status_code,
            false_text=false_resp.text,
            false_status=false_resp.status_code,
            url=request.url,
            method=request.method,
            param=point.locator,
            true_payload=true_payload,
            false_payload=false_payload,
            response_time=max(true_resp.elapsed, false_resp.elapsed),
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _run_boolean_form_check(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        true_payload: str,
        false_payload: str,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.boolean_trials))
        successful_trials = 0
        trial_records: List[tuple[Response, Response]] = []

        for _ in range(attempts):
            true_resp = self._send_form_variant(form, point, true_payload)
            false_resp = self._send_form_variant(form, point, false_payload)
            if true_resp.status_code == 0 or false_resp.status_code == 0:
                continue

            if self._boolean_trial_succeeded(baseline_resp, true_resp, false_resp):
                successful_trials += 1
                trial_records.append((true_resp, false_resp))

        if successful_trials != attempts or not trial_records:
            return None

        true_resp, false_resp = trial_records[-1]
        return self.detect_boolean_finding(
            baseline_text=baseline_resp.text,
            baseline_status=baseline_resp.status_code,
            true_text=true_resp.text,
            true_status=true_resp.status_code,
            false_text=false_resp.text,
            false_status=false_resp.status_code,
            url=form.absolute_action(),
            method=form.method.upper(),
            param=point.locator,
            true_payload=true_payload,
            false_payload=false_payload,
            response_time=max(true_resp.elapsed, false_resp.elapsed),
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _run_time_request_check(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
        delay_payload: str,
        control_payload: str | None,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.time_trials))
        successful_trials = 0
        trial_records: List[tuple[Response, Optional[Response]]] = []

        for _ in range(attempts):
            delay_resp = self._send_request_variant(request, point, delay_payload)
            if delay_resp.status_code == 0:
                continue

            control_resp = None
            if control_payload:
                control_resp = self._send_request_variant(request, point, control_payload)
                if control_resp.status_code == 0:
                    control_resp = None

            if self._time_trial_succeeded(baseline_resp, delay_resp, control_resp):
                successful_trials += 1
                trial_records.append((delay_resp, control_resp))

        if successful_trials != attempts or not trial_records:
            return None

        delay_resp, control_resp = trial_records[-1]
        return self.detect_time_finding(
            baseline_resp=baseline_resp,
            delay_resp=delay_resp,
            control_resp=control_resp,
            url=request.url,
            method=request.method,
            param=point.locator,
            delay_payload=delay_payload,
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _run_time_form_check(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
        delay_payload: str,
        control_payload: str | None,
    ) -> SQLiFinding | None:
        attempts = max(1, int(self.config.sqli.time_trials))
        successful_trials = 0
        trial_records: List[tuple[Response, Optional[Response]]] = []

        for _ in range(attempts):
            delay_resp = self._send_form_variant(form, point, delay_payload)
            if delay_resp.status_code == 0:
                continue

            control_resp = None
            if control_payload:
                control_resp = self._send_form_variant(form, point, control_payload)
                if control_resp.status_code == 0:
                    control_resp = None

            if self._time_trial_succeeded(baseline_resp, delay_resp, control_resp):
                successful_trials += 1
                trial_records.append((delay_resp, control_resp))

        if successful_trials != attempts or not trial_records:
            return None

        delay_resp, control_resp = trial_records[-1]
        return self.detect_time_finding(
            baseline_resp=baseline_resp,
            delay_resp=delay_resp,
            control_resp=control_resp,
            url=form.absolute_action(),
            method=form.method.upper(),
            param=point.locator,
            delay_payload=delay_payload,
            trials_run=attempts,
            successful_trials=successful_trials,
        )

    def _boolean_trial_succeeded(
        self,
        baseline_resp: Response,
        true_resp: Response,
        false_resp: Response,
    ) -> bool:
        if not self._statuses_allow_blind(
            baseline_resp.status_code,
            true_resp.status_code,
            false_resp.status_code,
        ):
            return False

        sim_true = self.similarity(baseline_resp.text, true_resp.text)
        sim_false = self.similarity(baseline_resp.text, false_resp.text)
        gap = abs(sim_true - sim_false)
        if gap < self.config.sqli.boolean_min_gap:
            return False

        # Для proof-режима требуем, чтобы true был ближе к baseline, чем false.
        return sim_true > sim_false

    def _time_trial_succeeded(
        self,
        baseline_resp: Response,
        delay_resp: Response,
        control_resp: Optional[Response],
    ) -> bool:
        compared_statuses = [baseline_resp.status_code, delay_resp.status_code]
        if control_resp is not None:
            compared_statuses.append(control_resp.status_code)
        if not self._statuses_allow_blind(*compared_statuses):
            return False

        threshold = max(1.0, float(self.config.sqli.time_based_delay) - 1.0)
        reference_time = baseline_resp.elapsed
        if control_resp is not None:
            reference_time = max(reference_time, control_resp.elapsed)

        return (delay_resp.elapsed - reference_time) >= threshold

    def _collect_baseline(self, requester) -> Optional[Response]:
        attempts = max(1, self.config.sqli.baseline_samples)
        responses: List[Response] = []
        for _ in range(attempts):
            resp = requester()
            if resp.status_code != 0:
                responses.append(resp)

        if not responses:
            return None

        statuses = [response.status_code for response in responses]
        dominant_status, count = Counter(statuses).most_common(1)[0]
        if attempts > 1 and count < 2:
            return None

        selected = [response for response in responses if response.status_code == dominant_status]
        if not selected:
            return None

        baseline = selected[0]
        baseline.elapsed = float(median([response.elapsed for response in selected]))
        return baseline

    def _derive_request_context(
        self,
        point: InputPoint,
        request: ObservedRequest,
        baseline_resp: Response,
    ) -> Dict[str, object]:
        quote_resp = self._send_request_variant(request, point, "'")
        numeric_resp = self._send_request_variant(request, point, "1-1")
        return derive_param_context(
            baseline_status=baseline_resp.status_code,
            baseline_text=baseline_resp.text,
            quote_status=quote_resp.status_code or baseline_resp.status_code,
            quote_text=quote_resp.text if quote_resp.status_code else baseline_resp.text,
            numeric_status=numeric_resp.status_code or baseline_resp.status_code,
            numeric_text=numeric_resp.text if numeric_resp.status_code else baseline_resp.text,
        )

    def _derive_form_context(
        self,
        point: InputPoint,
        form: Form,
        baseline_resp: Response,
    ) -> Dict[str, object]:
        quote_resp = self._send_form_variant(form, point, "'")
        numeric_resp = self._send_form_variant(form, point, "1-1")
        return derive_param_context(
            baseline_status=baseline_resp.status_code,
            baseline_text=baseline_resp.text,
            quote_status=quote_resp.status_code or baseline_resp.status_code,
            quote_text=quote_resp.text if quote_resp.status_code else baseline_resp.text,
            numeric_status=numeric_resp.status_code or baseline_resp.status_code,
            numeric_text=numeric_resp.text if numeric_resp.status_code else baseline_resp.text,
        )

    def _send_request_variant(
        self,
        request: ObservedRequest,
        point: InputPoint,
        value: Any,
    ) -> Response:
        params = copy.deepcopy(request.query_params or {})
        json_data = None
        headers = self._safe_headers_for_replay(request.headers or {}, request.content_type)

        if point.kind == "query":
            params[point.locator] = [str(value)] if value is not None else []
        elif point.kind == "json_field":
            json_data = copy.deepcopy(request.json_body)
            self._set_json_path_value(json_data, point.locator, value)
        else:
            return Response(request.url, 0, "", {}, 0.0, error="unsupported_point_kind")

        method = request.method.upper()
        if method == "GET":
            return self.transport.request(
                method,
                request.url,
                params=self._flatten_params(params),
                headers=headers,
            )

        if json_data is not None:
            return self.transport.request(
                method,
                request.url,
                params=self._flatten_params(params),
                json_data=json_data,
                headers=headers,
            )

        body_data = self._flatten_params(copy.deepcopy(request.form_fields or {}))
        if point.kind == "query":
            return self.transport.request(
                method,
                request.url,
                params=self._flatten_params(params),
                data=body_data if body_data else None,
                headers=headers,
            )

        return self.transport.request(
            method,
            request.url,
            params=self._flatten_params(params),
            headers=headers,
        )

    def _send_form_variant(self, form: Form, point: InputPoint, value: Any) -> Response:
        use_browser = bool(self.transport.browser and form.dom_index is not None)
        data = build_form_data(form, override_fields={point.locator: value})
        method = form.method.upper()
        action = form.absolute_action()
        if method == "GET":
            return self.transport.request(
                method,
                action,
                params=data,
                use_browser=use_browser,
                form=form,
            )
        return self.transport.request(
            method,
            action,
            data=data,
            use_browser=use_browser,
            form=form,
        )

    @staticmethod
    def _safe_headers_for_replay(headers: Dict[str, Any], content_type: str | None) -> Dict[str, str]:
        allowed: Dict[str, str] = {}
        blocked_prefixes = ("sec-",)
        blocked_names = {
            "cookie",
            "content-length",
            "host",
            "connection",
            "accept-encoding",
        }

        for name, value in headers.items():
            lowered = str(name).strip().lower()
            if not lowered or lowered in blocked_names:
                continue
            if any(lowered.startswith(prefix) for prefix in blocked_prefixes):
                continue
            allowed[lowered] = str(value)

        if content_type:
            allowed["content-type"] = str(content_type)
        return allowed

    @staticmethod
    def _flatten_params(params: Dict[str, List[str]]) -> Dict[str, Any]:
        flattened: Dict[str, Any] = {}
        for key, values in params.items():
            if not values:
                continue
            if len(values) == 1:
                flattened[key] = values[0]
            else:
                flattened[key] = list(values)
        return flattened

    @staticmethod
    def _set_json_path_value(payload: Any, path: str, value: Any):
        tokens = SQLiScanner._parse_json_path(path)
        if not tokens or payload is None:
            return

        current = payload
        for token in tokens[:-1]:
            current = current[token]
        current[tokens[-1]] = value

    @staticmethod
    def _parse_json_path(path: str) -> List[Any]:
        tokens: List[Any] = []
        i = 0
        while i < len(path):
            char = path[i]
            if char == "$":
                i += 1
                continue
            if char == ".":
                i += 1
                start = i
                while i < len(path) and path[i] not in ".[":
                    i += 1
                tokens.append(path[start:i])
                continue
            if char == "[":
                i += 1
                start = i
                while i < len(path) and path[i] != "]":
                    i += 1
                tokens.append(int(path[start:i]))
                i += 1
                continue
            i += 1
        return tokens

    @staticmethod
    def _index_requests(requests: List[ObservedRequest]) -> Dict[tuple[str, str, str], ObservedRequest]:
        indexed: Dict[tuple[str, str, str], ObservedRequest] = {}
        for request in requests:
            indexed[(request.url, request.method.upper(), request.source_kind)] = request
        return indexed

    @staticmethod
    def _index_forms(forms: List[Form]) -> Dict[tuple[str, str, str], Form]:
        indexed: Dict[tuple[str, str, str], Form] = {}
        for form in forms:
            action = form.absolute_action()
            method = form.method.upper()
            for field in form.inputs:
                name = str(field.name or "").strip()
                if name:
                    indexed[(action, method, name)] = form
        return indexed

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

    @staticmethod
    def _statuses_allow_blind(*statuses: int) -> bool:
        for status in statuses:
            if 500 <= status < 600:
                return False
        return True

    def _resolve_boolean_check_source(self) -> List[Dict[str, Any] | tuple[str, str]]:
        if self.config.sqli.boolean_checks:
            return list(self.config.sqli.boolean_checks)

        if self.config.sqli.boolean_payload_pairs:
            return list(self.config.sqli.boolean_payload_pairs)

        true_payloads = list(self.config.sqli.boolean_true_payloads or [])
        false_payloads = list(self.config.sqli.boolean_false_payloads or [])
        return list(zip(true_payloads, false_payloads))
