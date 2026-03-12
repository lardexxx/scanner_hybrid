# crawler_dynamic.py

from collections import deque
from typing import List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from config import ScannerConfig
from transport import Transport
from state import ScannerState, normalize_url
from form_extraction import extract_forms_from_soup
from models import Page, Form, InputField


class DynamicCrawler:

    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self.base_domain = urlparse(config.target_url).netloc.lower()

    # ===============================
    # Public crawl
    # ===============================

    def crawl(self) -> List[Page]:

        if not self.transport.browser:
            raise RuntimeError("DynamicCrawler requires browser enabled in config.")

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

            response = self.transport.request("GET", url, use_browser=True)

            if response.status_code == 0 or response.status_code >= 400:
                if response.status_code == 0 and response.error:
                    print(f"[!] Dynamic crawl request failed: {url} ({response.error})")
                elif response.status_code >= 400:
                    print(f"[!] Dynamic crawl HTTP {response.status_code}: {url}")
                continue

            self.state.mark_visited(url)

            # Ждём сетевую стабилизацию (важно для SPA)
            self.transport.browser.page.wait_for_load_state("networkidle")

            content = self.transport.browser.page.content()

            page = Page(
                url=self.transport.browser.page.url,
                status_code=response.status_code,
                content=content,
                depth=depth,
            )

            soup = BeautifulSoup(content, "html.parser")

            links = self.extract_links(soup, page.url)
            page.links = links

            if self.config.crawler.extract_forms:
                forms = self.extract_forms(soup, page.url)
                page.forms = forms

            pages.append(page)

            for link in links:
                if self.should_follow(link):
                    if not self.state.is_queued(link):
                        queue.append((link, depth + 1))
                        self.state.mark_queued(link)

        return pages

    # ===============================
    # Extract links (DOM rendered)
    # ===============================

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        links = []

        # Стандартные <a href>
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if not self.is_good_link(href):
                continue
            absolute = urljoin(base_url, href)
            links.append(normalize_url(absolute))

        # JS-based links (onclick)
        if self.config.crawler.extract_js_links:
            for tag in soup.find_all(onclick=True):
                onclick = tag.get("onclick", "")
                if "location" in onclick or "href" in onclick:
                    # Primitive parsing of JS redirections.
                    parts = onclick.split("'")
                    if len(parts) >= 2:
                        candidate = parts[1]
                        if not self.is_good_link(candidate):
                            continue
                        absolute = urljoin(base_url, candidate)
                        links.append(normalize_url(absolute))

        return links

    # ===============================
    # Extract forms (rendered DOM)
    # ===============================

    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Form]:
        if self.transport.browser:
            try:
                return self._extract_forms_from_dom(base_url)
            except Exception:
                pass
        return extract_forms_from_soup(soup, base_url)

    def _extract_forms_from_dom(self, base_url: str) -> List[Form]:
        page = self.transport.browser.page
        form_rows = page.evaluate(
            """
            () => {
              const isDisabled = (el) => {
                if (el.disabled) return true;
                let parent = el.parentElement;
                while (parent) {
                  if (parent.tagName === "FIELDSET" && parent.disabled) {
                    const firstLegend = parent.querySelector(":scope > legend");
                    if (firstLegend && firstLegend.contains(el)) {
                      return false;
                    }
                    return true;
                  }
                  parent = parent.parentElement;
                }
                return false;
              };

              return Array.from(document.forms).map((form) => {
                const controls = [];
                for (const el of Array.from(form.elements)) {
                  if (!el || !el.name || isDisabled(el)) continue;
                  const tag = (el.tagName || "").toLowerCase();
                  const type = ((el.type || tag || "text") + "").toLowerCase();

                  if (tag === "input") {
                    if (["submit", "button", "reset", "file", "image"].includes(type)) continue;
                    if (["checkbox", "radio"].includes(type) && !el.checked) continue;
                    let value = el.value;
                    if ((type === "checkbox" || type === "radio") && !value) value = "on";
                    if (type === "hidden" && value == null) value = "";
                    controls.push({ name: el.name, input_type: type, value: value ?? null });
                    continue;
                  }

                  if (tag === "textarea") {
                    controls.push({ name: el.name, input_type: "textarea", value: el.value ?? "" });
                    continue;
                  }

                  if (tag === "select") {
                    let value = "";
                    if (el.selectedOptions && el.selectedOptions.length > 0) {
                      value = el.selectedOptions[0].value || el.selectedOptions[0].text || "";
                    } else if (el.options && el.options.length > 0) {
                      value = el.options[0].value || el.options[0].text || "";
                    }
                    controls.push({ name: el.name, input_type: "select", value });
                  }
                }

                return {
                  action: form.getAttribute("action") || "",
                  method: (form.getAttribute("method") || "GET").toUpperCase(),
                  enctype: form.getAttribute("enctype") || "application/x-www-form-urlencoded",
                  inputs: controls,
                };
              });
            }
            """
        )

        forms: List[Form] = []
        for row in form_rows:
            inputs = [
                InputField(
                    name=str(item.get("name", "")).strip(),
                    input_type=str(item.get("input_type", "text")).strip(),
                    value=item.get("value"),
                )
                for item in row.get("inputs", [])
                if str(item.get("name", "")).strip()
            ]
            forms.append(
                Form(
                    action=str(row.get("action", "")),
                    method=str(row.get("method", "GET")).upper(),
                    inputs=inputs,
                    source_url=base_url,
                    enctype=str(
                        row.get("enctype", "application/x-www-form-urlencoded")
                    ).strip(),
                )
            )
        return forms

    # ===============================
    # Domain filter
    # ===============================

    def should_follow(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not self.config.crawler.follow_external:
            return domain == self.base_domain

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
