# core.py

from typing import List

from config import ScannerConfig
from transport import Transport
from state import ScannerState

from crawler_static import StaticCrawler
from crawler_dynamic import DynamicCrawler

from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.csrf_scanner import CSRFScanner

from models import ScanResult, Page


class ScannerCore:

    def __init__(self, config: ScannerConfig):
        self.config = config

        # инфраструктура
        self.transport = Transport(config)
        self.state = ScannerState(config.crawler.max_pages)

        # краулеры
        self.static_crawler = StaticCrawler(config, self.transport, self.state)

        if config.use_browser:
            self.dynamic_crawler = DynamicCrawler(config, self.transport, self.state)
        else:
            self.dynamic_crawler = None

        # сканеры
        self.xss_scanner = XSSScanner(config, self.transport, self.state)
        self.sqli_scanner = SQLiScanner(config, self.transport, self.state)
        self.csrf_scanner = CSRFScanner(config, self.transport, self.state)

    # ===============================
    # Full scan
    # ===============================

    def run(self) -> ScanResult:

        print("[*] Starting scan:", self.config.target_url)

        # 1️⃣ Static crawl
        print("[*] Static crawling...")
        pages_static = self.static_crawler.crawl()

        print(f"[+] Static pages discovered: {len(pages_static)}")

        pages = pages_static

        # 2️⃣ Dynamic crawl (если браузер включен)
        if self.dynamic_crawler:
            print("[*] Dynamic crawling (JS)...")

            pages_dynamic = self.dynamic_crawler.crawl()

            print(f"[+] Dynamic pages discovered: {len(pages_dynamic)}")

            pages = self.merge_pages(pages_static, pages_dynamic)

        print(f"[+] Total unique pages: {len(pages)}")

        # ===============================
        # Security scanning
        # ===============================

        xss_findings = []
        sqli_findings = []
        csrf_findings = []

        # XSS
        if self.config.xss.enabled:
            print("[*] Scanning for XSS...")
            xss_findings = self.xss_scanner.scan_pages(pages)
            print(f"[+] XSS findings: {len(xss_findings)}")

        # SQLi
        if self.config.sqli.enabled:
            print("[*] Scanning for SQLi...")
            sqli_findings = self.sqli_scanner.scan_pages(pages)
            print(f"[+] SQLi findings: {len(sqli_findings)}")

        # CSRF
        if self.config.csrf.enabled:
            print("[*] Scanning for CSRF...")
            csrf_findings = self.csrf_scanner.scan_pages(pages)
            print(f"[+] CSRF findings: {len(csrf_findings)}")

        # ===============================
        # Aggregation
        # ===============================

        result = ScanResult(
            target=self.config.target_url,
            pages_scanned=len(pages),
            xss_findings=xss_findings,
            sqli_findings=sqli_findings,
            csrf_findings=csrf_findings
        )

        return result

    # ===============================
    # Merge static + dynamic pages
    # ===============================

    def merge_pages(self, static_pages: List[Page], dynamic_pages: List[Page]) -> List[Page]:

        page_map = {}

        for p in static_pages:
            page_map[p.url] = p

        for p in dynamic_pages:
            if p.url not in page_map:
                page_map[p.url] = p
            else:
                # объединяем формы и ссылки
                existing = page_map[p.url]

                existing.links = list(set(existing.links + p.links))
                existing.forms = existing.forms + p.forms

        return list(page_map.values())

    # ===============================
    # Shutdown
    # ===============================

    def shutdown(self):
        print("[*] Shutting down scanner...")
        self.transport.close()