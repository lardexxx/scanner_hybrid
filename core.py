from typing import List

from config import ScannerConfig
from crawler_dynamic import DynamicCrawler
from crawler_static import StaticCrawler
from discovery_utils import dedupe_input_points, dedupe_requests
from models import Form, InputField, Page, ScanResult
from scanners.sqli_scanner import SQLiScanner
from setupe_urls import ScannerState
from transport import Transport


class ScannerCore:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.transport = Transport(config)
        self.state = ScannerState(config.crawler.max_pages)

        # Общий discovery слой.
        self.static_crawler = StaticCrawler(config, self.transport, self.state)
        self.dynamic_crawler = (
            DynamicCrawler(config, self.transport, self.state)
            if config.use_browser
            else None
        )

        # На текущем этапе включен только SQLi.
        self.sqli_scanner = SQLiScanner(config, self.transport, self.state)

    def run(self) -> ScanResult:
        print("[*] Starting scan:", self.config.target_url)

        print("[*] Static crawling...")
        pages_static = self.static_crawler.crawl()
        print(f"[+] Static pages discovered: {len(pages_static)}")

        pages = pages_static
        if self.dynamic_crawler:
            print("[*] Dynamic crawling (JS)...")
            self.state.reset_crawl_tracking()
            pages_dynamic = self.dynamic_crawler.crawl()
            self.transport.sync_browser_cookies_to_http()
            print(f"[+] Dynamic pages discovered: {len(pages_dynamic)}")
            pages = self.merge_pages(pages_static, pages_dynamic)

        print(f"[+] Total unique pages: {len(pages)}")

        sqli_findings = []
        if self.config.sqli.enabled:
            print("[*] Scanning for SQLi...")
            sqli_findings = self.sqli_scanner.scan_pages(pages)
            print(f"[+] SQLi findings: {len(sqli_findings)}")

        return ScanResult(
            target=self.config.target_url,
            pages_scanned=len(pages),
            sqli_findings=sqli_findings,
        )

    def merge_pages(self, static_pages: List[Page], dynamic_pages: List[Page]) -> List[Page]:
        # Объединяем артефакты discovery из static и dynamic обхода.
        page_map: dict[str, Page] = {}

        for page in static_pages:
            page_map[page.url] = page

        for page in dynamic_pages:
            existing = page_map.get(page.url)
            if existing is None:
                page_map[page.url] = page
                continue

            existing.links = self.merge_links(existing.links, page.links)
            existing.forms = self.merge_forms(existing.forms, page.forms)
            existing.observed_requests = dedupe_requests(
                (existing.observed_requests or []) + (page.observed_requests or [])
            )
            existing.input_points = dedupe_input_points(
                (existing.input_points or []) + (page.input_points or [])
            )

            if page.content:
                existing.content = page.content
            if page.status_code:
                existing.status_code = page.status_code

        return list(page_map.values())

    @staticmethod
    def merge_links(static_links: List[str], dynamic_links: List[str]) -> List[str]:
        merged: List[str] = []
        seen: set[str] = set()

        for link in (static_links or []) + (dynamic_links or []):
            if link in seen:
                continue
            seen.add(link)
            merged.append(link)

        return merged

    @staticmethod
    def merge_forms(static_forms: List[Form], dynamic_forms: List[Form]) -> List[Form]:
        merged: List[Form] = []
        form_map = {}

        for form in static_forms or []:
            key = ScannerCore.form_merge_key(form)
            form_map[key] = form
            merged.append(form)

        for form in dynamic_forms or []:
            key = ScannerCore.form_merge_key(form)
            existing = form_map.get(key)
            if existing is None:
                form_map[key] = form
                merged.append(form)
                continue

            replacement = ScannerCore.prefer_dynamic_form(existing, form)
            index = merged.index(existing)
            merged[index] = replacement
            form_map[key] = replacement

        return merged

    @staticmethod
    def form_merge_key(form: Form) -> tuple:
        return (
            form.absolute_action(),
            (form.method or "GET").upper(),
            (form.enctype or "").strip().lower(),
            tuple(ScannerCore.control_signature(inp) for inp in form.inputs),
            tuple(ScannerCore.control_signature(inp) for inp in form.submit_controls or []),
        )

    @staticmethod
    def control_signature(field: InputField) -> tuple[str, str]:
        return (
            (field.name or "").strip(),
            (field.input_type or "").strip().lower(),
        )

    @staticmethod
    def prefer_dynamic_form(static_form: Form, dynamic_form: Form) -> Form:
        if len(dynamic_form.inputs) < len(static_form.inputs):
            return static_form
        return dynamic_form

    def shutdown(self):
        print("[*] Shutting down scanner...")
        self.transport.close()
