# transport.py

import time
import requests
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from config import ScannerConfig


# ===============================
# Unified Response Model
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
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Response:

        start = time.time()

        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
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
        self.context.add_init_script(
            """
            (() => {
              window.__xss_exec_marker = false;
              const oldAlert = window.alert;
              const oldConfirm = window.confirm;
              const oldPrompt = window.prompt;

              window.alert = function(...args) {
                window.__xss_exec_marker = true;
                if (typeof oldAlert === "function") {
                  return oldAlert.apply(window, args);
                }
                return undefined;
              };
              window.confirm = function(...args) {
                window.__xss_exec_marker = true;
                if (typeof oldConfirm === "function") {
                  return oldConfirm.apply(window, args);
                }
                return true;
              };
              window.prompt = function(...args) {
                window.__xss_exec_marker = true;
                if (typeof oldPrompt === "function") {
                  return oldPrompt.apply(window, args);
                }
                return "";
              };
            })();
            """
        )
        self.page = self.context.new_page()

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
    ) -> Response:

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
                error=str(exc),
            )

    def close(self):
        self.context.close()
        self.browser.close()
        self.playwright.stop()

    def reset_xss_marker(self):
        try:
            self.page.evaluate("() => { window.__xss_exec_marker = false; }")
        except Exception:
            pass

    def read_xss_marker(self) -> bool:
        try:
            return bool(self.page.evaluate("() => Boolean(window.__xss_exec_marker)"))
        except Exception:
            return False

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
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        use_browser: bool = False,
    ) -> Response:

        if use_browser and self.browser:
            if method.upper() == "GET":
                return self.browser.navigate(url, params=params)
            else:
                return self.browser.submit_form(url, method, data or {})
        else:
            return self.http.request(method, url, params, data)

    def close(self):
        if self.browser:
            self.browser.close()
