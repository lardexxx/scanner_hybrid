from collections import deque
from typing import List

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from config import ScannerConfig
from discovery_utils import (
    build_navigation_request,
    dedupe_input_points,
    extract_form_input_points,
    extract_query_input_points,
)
from form_extraction import extract_forms_from_soup
from models import InputPoint, Page
from setupe_urls import ScannerState, normalize_url
from transport import Transport


class StaticCrawler:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self.base_domain = urlparse(config.target_url).netloc.lower()

    def crawl(self) -> List[Page]:
        # Статический обход собирает только то, что реально видно в HTML и URL.
        queue = deque([(self.config.target_url, 0)])
        pages: List[Page] = []
        self.state.mark_queued(self.config.target_url)

        while queue:
            url, depth = queue.popleft()
            normalized_url = normalize_url(url)

            if depth > self.config.crawler.max_depth:
                continue
            if not self.state.should_visit(normalized_url):
                continue

            response = self.transport.request("GET", normalized_url)
            if response.status_code == 0 or response.status_code >= 400:
                if response.status_code == 0 and response.error:
                    print(f"[!] Static crawl request failed: {normalized_url} ({response.error})")
                elif response.status_code >= 400:
                    print(f"[!] Static crawl HTTP {response.status_code}: {normalized_url}")
                continue

            self.state.mark_visited(normalized_url)
            page = Page(
                url=response.url,
                status_code=response.status_code,
                content=response.text,
                depth=depth,
            )

            navigation_request = build_navigation_request(
                url=response.url,
                source_page_url=response.url,
                source_kind="navigation",
                method="GET",
                status_code=response.status_code,
                headers=response.headers,
            )
            page.observed_requests.append(navigation_request)

            soup = BeautifulSoup(response.text, "html.parser")
            page.links = self.extract_links(soup, response.url)

            input_points: List[InputPoint] = []
            input_points.extend(extract_query_input_points(navigation_request))

            if self.config.crawler.extract_forms:
                page.forms = self.extract_forms(soup, response.url)
                for form in page.forms:
                    input_points.extend(extract_form_input_points(form))

            page.input_points = dedupe_input_points(input_points)
            pages.append(page)

            for link in page.links:
                if not self.should_follow(link):
                    continue
                if self.state.is_queued(link):
                    continue
                queue.append((link, depth + 1))
                self.state.mark_queued(link)

        return pages

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        # Берем только реальные HTTP-ссылки из HTML.
        links: List[str] = []
        seen: set[str] = set()

        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if not self.is_good_link(href):
                continue
            absolute = normalize_url(urljoin(base_url, href))
            if absolute in seen:
                continue
            seen.add(absolute)
            links.append(absolute)

        return links

    def extract_forms(self, soup: BeautifulSoup, base_url: str):
        return extract_forms_from_soup(soup, base_url)

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
