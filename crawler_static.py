# crawler_static.py

from collections import deque
from typing import List
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from transport import Transport
from config import ScannerConfig
from form_extraction import extract_forms_from_soup
from models import Page, Form
from state import ScannerState, normalize_url


class StaticCrawler:

    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self.base_domain = urlparse(config.target_url).netloc.lower()

    # ===============================
    # Public crawl method
    # ===============================

    def crawl(self) -> List[Page]:

        queue = deque()
        pages: List[Page] = []

        queue.append((self.config.target_url, 0))
        self.state.mark_queued(self.config.target_url)

        while queue:
            url, depth = queue.popleft()
            url = normalize_url(url)

            if depth > self.config.crawler.max_depth:
                continue

            if not self.state.should_visit(url):
                continue

            response = self.transport.request("GET", url)

            if response.status_code == 0 or response.status_code >= 400:
                if response.status_code == 0 and response.error:
                    print(f"[!] Static crawl request failed: {url} ({response.error})")
                elif response.status_code >= 400:
                    print(f"[!] Static crawl HTTP {response.status_code}: {url}")
                continue

            self.state.mark_visited(url)

            page = Page(
                url=response.url,
                status_code=response.status_code,
                content=response.text,
                depth=depth,
            )

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract links
            links = self.extract_links(soup, response.url)
            page.links = links

            # Extract forms
            if self.config.crawler.extract_forms:
                forms = self.extract_forms(soup, response.url)
                page.forms = forms

            pages.append(page)

            # Add new links to queue
            for link in links:
                if self.should_follow(link):
                    if not self.state.is_queued(link):
                        queue.append((link, depth + 1))
                        self.state.mark_queued(link)

        return pages

    # ===============================
    # Link extraction
    # ===============================

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if not self.is_good_link(href):
                continue
            absolute = urljoin(base_url, href)
            normalized = normalize_url(absolute)
            links.append(normalized)

        return links

    # ===============================
    # Form extraction
    # ===============================

    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Form]:
        return extract_forms_from_soup(soup, base_url)

    # ===============================
    # Domain filtering
    # ===============================

    def should_follow(self, url: str) -> bool:
        parsed = urlparse(url)
        target_domain = parsed.netloc.lower()

        if not self.config.crawler.follow_external:
            return target_domain == self.base_domain

        return True

    @staticmethod
    def is_good_link(href: str) -> bool:
        lowered = (href or "").strip().lower()
        if not lowered:
            return False
        if lowered.startswith("#"):
            return False
        if lowered.startswith("javascript:"):
            return False
        if lowered.startswith("mailto:"):
            return False
        if lowered.startswith("tel:"):
            return False
        return True
