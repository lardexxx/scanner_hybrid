# transport.py

import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from config import ScannerConfig
from models import Form


# ===============================
# Модель ответа для
# ===============================

class Response:
    def __init__(
        self,
        url: str,
        status_code: int,
        text: str,
        headers: Dict[str, str],
        elapsed: float,
        error: str | None = None,
    ):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.elapsed = elapsed
        self.error = error


# ===============================
# HTTP Client (requests)
# ===============================

class HTTPClient:

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.request.user_agent
        })

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Any = None,
        headers: Optional[Dict[str, Any]] = None,
    ) -> Response:

        start = time.time()

        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                timeout=self.config.request.timeout,
                verify=self.config.request.verify_ssl,
                allow_redirects=self.config.request.allow_redirects,
            )

            elapsed = time.time() - start

            return Response(
                url=resp.url,
                status_code=resp.status_code,
                text=resp.text,
                headers=dict(resp.headers),
                elapsed=elapsed,
            )
        except requests.RequestException as exc:
            elapsed = time.time() - start
            return Response(
                url=url,
                status_code=0,
                text="",
                headers={},
                elapsed=elapsed,
                error=str(exc),
            )


# ===============================
# Browser Client (Playwright)
# ===============================

class BrowserClient:

    def __init__(self, config: ScannerConfig):
        try:
            from playwright.sync_api import sync_playwright  # lazy import
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed. Set use_browser=False or install playwright."
            ) from exc

        self.config = config
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=self.config.browser.headless,
            slow_mo=self.config.browser.slow_mo,
        )
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        self._observed_requests: List[Dict[str, Any]] = []
        self.page.on("request", self._capture_request)

    def navigate(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Response:

        start = time.time()
        target_url = self._build_url(url, params)

        try:
            response = self.page.goto(
                target_url,
                timeout=self.config.browser.timeout,
                wait_until=self.config.browser.wait_until,
            )

            elapsed = time.time() - start

            content = self.page.content()
            status = response.status if response else 0
            headers = response.headers if response else {}

            return Response(
                url=self.page.url,
                status_code=status,
                text=content,
                headers=headers,
                elapsed=elapsed,
            )
        except Exception as exc:
            elapsed = time.time() - start
            return Response(
                url=target_url,
                status_code=0,
                text="",
                headers={},
                elapsed=elapsed,
                error=str(exc),
            )

    def submit_form(
        self,
        url: str,
        method: str,
        data: Dict[str, Any],
        form: Form | None = None,
    ) -> Response:

        dom_submit_error = None
        if form is not None and form.dom_index is not None:
            try:
                return self._submit_form_via_dom(form, data)
            except Exception as exc:
                dom_submit_error = exc

        if method.upper() == "GET":
            return self.navigate(url, params=data)

        start = time.time()

        try:
            response = self.page.request.post(url, data=data)

            elapsed = time.time() - start

            return Response(
                url=response.url,
                status_code=response.status,
                text=response.text(),
                headers=response.headers,
                elapsed=elapsed,
            )
        except Exception as exc:
            elapsed = time.time() - start
            return Response(
                url=url,
                status_code=0,
                text="",
                headers={},
                elapsed=elapsed,
                error=str(dom_submit_error or exc),
            )

    def close(self):
        self.context.close()
        self.browser.close()
        self.playwright.stop()

    def reset_observed_requests(self):
        # Перед новой навигацией очищаем пассивно собранные browser requests.
        self._observed_requests = []

    def drain_observed_requests(self) -> List[Dict[str, Any]]:
        requests = list(self._observed_requests)
        self._observed_requests = []
        return requests

    def export_cookies(self) -> List[Dict[str, Any]]:
        try:
            return self.context.cookies()
        except Exception:
            return []

    def _submit_form_via_dom(self, form: Form, data: Dict[str, Any]) -> Response:
        start = time.time()
        self.page.goto(
            form.source_url,
            timeout=self.config.browser.timeout,
            wait_until=self.config.browser.wait_until,
        )
        try:
            self.page.wait_for_load_state("networkidle", timeout=self.config.browser.timeout)
        except Exception:
            pass

        last_document_response = {"response": None}

        def on_response(response):
            try:
                request = response.request
                if request.resource_type == "document" and request.frame == self.page.main_frame:
                    last_document_response["response"] = response
            except Exception:
                pass

        payload = {
            "locator": self._form_locator_payload(form),
            "formData": data,
        }

        self.page.on("response", on_response)
        try:
            self.page.evaluate(
                """
                ({ locator, formData }) => {
                  const forms = Array.from(document.forms);

                  const normalizeSignature = (items) =>
                    (items || []).map((item) => ({
                      name: String(item?.name || "").trim(),
                      input_type: String(item?.input_type || "").trim().toLowerCase(),
                    }));

                  const sameSignature = (left, right) => {
                    if (left.length !== right.length) return false;
                    for (let i = 0; i < left.length; i += 1) {
                      if (left[i].name !== right[i].name || left[i].input_type !== right[i].input_type) {
                        return false;
                      }
                    }
                    return true;
                  };

                  const controlSignature = (el) => {
                    const tag = (el.tagName || "").toLowerCase();
                    const type = ((el.type || tag || "text") + "").toLowerCase();
                    if (tag === "button" && type === "submit") {
                      return { name: String(el.name || "").trim(), input_type: "button:submit" };
                    }
                    if (tag === "select" && el.multiple) {
                      return { name: String(el.name || "").trim(), input_type: "select-multiple" };
                    }
                    return { name: String(el.name || "").trim(), input_type: type };
                  };

                  const absoluteAction = (formEl) =>
                    new URL(formEl.getAttribute("action") || "", document.baseURI).toString();

                  const matchesTarget = (formEl) => {
                    const targetInputs = normalizeSignature(locator.inputs);
                    const targetSubmitters = normalizeSignature(locator.submit_controls);
                    const currentInputs = [];
                    const currentSubmitters = [];

                    for (const el of Array.from(formEl.elements)) {
                      if (!el || !el.name) continue;
                      const tag = (el.tagName || "").toLowerCase();
                      const signature = controlSignature(el);
                      if (tag === "button" && signature.input_type === "button:submit") {
                        currentSubmitters.push(signature);
                        continue;
                      }
                      if (tag === "input" && ["submit", "image"].includes(signature.input_type)) {
                        currentSubmitters.push(signature);
                        continue;
                      }
                      if (tag === "input" && ["reset", "file", "button"].includes(signature.input_type)) {
                        continue;
                      }
                      currentInputs.push(signature);
                    }

                    return (
                      absoluteAction(formEl) === locator.action &&
                      String(formEl.method || "GET").toUpperCase() === locator.method &&
                      sameSignature(currentInputs, targetInputs) &&
                      sameSignature(currentSubmitters, targetSubmitters)
                    );
                  };

                  let formEl = null;
                  if (
                    Number.isInteger(locator.dom_index) &&
                    locator.dom_index >= 0 &&
                    locator.dom_index < forms.length &&
                    matchesTarget(forms[locator.dom_index])
                  ) {
                    formEl = forms[locator.dom_index];
                  }
                  if (!formEl) {
                    formEl = forms.find((candidate) => matchesTarget(candidate)) || null;
                  }
                  if (!formEl) {
                    throw new Error("Target form not found in DOM");
                  }

                  const valuesFor = (name) => {
                    if (!Object.prototype.hasOwnProperty.call(formData, name)) {
                      return null;
                    }
                    const value = formData[name];
                    if (Array.isArray(value)) {
                      return value.map((item) => String(item));
                    }
                    return [String(value)];
                  };

                  for (const el of Array.from(formEl.elements)) {
                    if (!el || !el.name) continue;
                    const values = valuesFor(el.name);

                    const tag = (el.tagName || "").toLowerCase();
                    const type = ((el.type || tag || "text") + "").toLowerCase();

                    if (tag === "input") {
                      if (["submit", "image", "button", "reset", "file"].includes(type)) continue;
                      if (values === null) {
                        el.disabled = true;
                        continue;
                      }
                      if (type === "checkbox" || type === "radio") {
                        const currentValue = el.value || "on";
                        el.checked = values.includes(String(currentValue));
                      } else {
                        el.value = values[0] ?? "";
                      }
                      continue;
                    }

                    if (tag === "textarea") {
                      if (values === null) {
                        el.disabled = true;
                        continue;
                      }
                      el.value = values[0] ?? "";
                      continue;
                    }

                    if (tag === "select") {
                      if (values === null) {
                        el.disabled = true;
                        continue;
                      }
                      const allowed = new Set(values);
                      for (const option of Array.from(el.options)) {
                        option.selected = allowed.has(String(option.value || option.text || ""));
                      }
                      if (!el.multiple && values.length > 0 && el.value !== values[0]) {
                        el.value = values[0];
                      }
                    }
                  }

                  let submitter = null;
                  for (const candidate of Array.from(formEl.elements)) {
                    if (!candidate || !candidate.name) continue;
                    const tag = (candidate.tagName || "").toLowerCase();
                    const type = ((candidate.type || tag || "text") + "").toLowerCase();
                    if (!(tag === "button" && type === "submit") && !(tag === "input" && ["submit", "image"].includes(type))) {
                      continue;
                    }
                    const wanted = locator.submitter;
                    if (!wanted) {
                      submitter = candidate;
                      break;
                    }
                    if (candidate.name !== wanted.name) continue;
                    if (String(candidate.value || "") !== String(wanted.value || "")) continue;
                    submitter = candidate;
                    break;
                  }

                  if (typeof formEl.requestSubmit === "function") {
                    if (submitter) {
                      formEl.requestSubmit(submitter);
                    } else {
                      formEl.requestSubmit();
                    }
                  } else if (submitter && typeof submitter.click === "function") {
                    submitter.click();
                  } else {
                    formEl.submit();
                  }
                }
                """,
                payload,
            )

            try:
                self.page.wait_for_load_state(self.config.browser.wait_until, timeout=self.config.browser.timeout)
            except Exception:
                pass
            try:
                self.page.wait_for_load_state("networkidle", timeout=self.config.browser.timeout)
            except Exception:
                pass
            self.page.wait_for_timeout(150)

            elapsed = time.time() - start
            response = last_document_response["response"]
            return Response(
                url=self.page.url,
                status_code=response.status if response else 200,
                text=self.page.content(),
                headers=response.headers if response else {},
                elapsed=elapsed,
            )
        finally:
            try:
                self.page.remove_listener("response", on_response)
            except Exception:
                pass

    @staticmethod
    def _form_locator_payload(form: Form) -> Dict[str, Any]:
        submitter = None
        if form.submit_controls:
            submitter = {
                "name": form.submit_controls[0].name,
                "value": form.submit_controls[0].value if form.submit_controls[0].value is not None else "",
            }
        return {
            "dom_index": form.dom_index,
            "action": form.absolute_action(),
            "method": (form.method or "GET").upper(),
            "inputs": [
                {
                    "name": (field.name or "").strip(),
                    "input_type": (field.input_type or "").strip().lower(),
                }
                for field in form.inputs
                if (field.name or "").strip()
            ],
            "submit_controls": [
                {
                    "name": (field.name or "").strip(),
                    "input_type": (field.input_type or "").strip().lower(),
                }
                for field in form.submit_controls or []
                if (field.name or "").strip()
            ],
            "submitter": submitter,
        }

    @staticmethod
    def _build_url(url: str, params: Optional[Dict[str, Any]]) -> str:
        if not params:
            return url

        parsed = urlparse(url)
        existing_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        new_pairs = []
        for key, value in params.items():
            if isinstance(value, list):
                new_pairs.extend((key, item) for item in value)
            else:
                new_pairs.append((key, value))
        merged_query = urlencode(existing_pairs + new_pairs, doseq=True)
        return urlunparse(parsed._replace(query=merged_query))

    def _capture_request(self, request):
        # Сохраняем только реально наблюдаемые браузерные запросы без интерпретации.
        try:
            headers = self._safe_request_headers(request)
            raw_body = self._safe_request_post_data(request)
            self._observed_requests.append(
                {
                    "method": str(getattr(request, "method", "") or "").upper(),
                    "url": str(getattr(request, "url", "") or ""),
                    "resource_type": str(getattr(request, "resource_type", "") or ""),
                    "headers": headers,
                    "content_type": headers.get("content-type", ""),
                    "raw_body": raw_body,
                }
            )
        except Exception:
            pass

    @staticmethod
    def _safe_request_headers(request) -> Dict[str, str]:
        try:
            headers = getattr(request, "headers", {})
            if callable(headers):
                headers = headers()
            if isinstance(headers, dict):
                return {str(key).lower(): str(value) for key, value in headers.items()}
        except Exception:
            pass
        return {}

    @staticmethod
    def _safe_request_post_data(request) -> str | None:
        try:
            post_data = getattr(request, "post_data", None)
            if callable(post_data):
                post_data = post_data()
            if post_data is None:
                return None
            return str(post_data)
        except Exception:
            return None


# ===============================
# Transport Manager (Hybrid)
# ===============================

class Transport:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.http = HTTPClient(config)
        self.browser = BrowserClient(config) if config.use_browser else None

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Any = None,
        headers: Optional[Dict[str, Any]] = None,
        use_browser: bool = False,
        form: Form | None = None,
    ) -> Response:

        if use_browser and self.browser:
            if form is not None:
                browser_data = params if method.upper() == "GET" else data
                return self.browser.submit_form(url, method, browser_data or {}, form=form)
            if method.upper() == "GET":
                return self.browser.navigate(url, params=params)
            return self.browser.submit_form(url, method, data or {})
        return self.http.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json_data=json_data,
            headers=headers,
        )

    def sync_browser_cookies_to_http(self):
        # После dynamic crawl переносим реальные browser cookies в HTTP-сессию.
        if not self.browser:
            return

        for cookie in self.browser.export_cookies():
            name = str(cookie.get("name", "") or "")
            value = str(cookie.get("value", "") or "")
            domain = cookie.get("domain")
            path = str(cookie.get("path", "/") or "/")
            if not name:
                continue
            self.http.session.cookies.set(
                name,
                value,
                domain=str(domain) if domain else None,
                path=path,
            )

    def close(self):
        if self.browser:
            self.browser.close()
