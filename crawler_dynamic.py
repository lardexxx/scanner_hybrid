from collections import deque
from typing import List

from bs4 import BeautifulSoup
from urllib.parse import parse_qs, urljoin, urlparse

from config import ScannerConfig
from discovery_utils import (
    build_navigation_request,
    dedupe_input_points,
    dedupe_requests,
    extract_form_input_points,
    extract_json_input_points,
    extract_query_input_points,
    parse_request_body,
)
from form_extraction import extract_forms_from_soup
from models import Form, InputField, InputPoint, ObservedRequest, Page
from setupe_urls import ScannerState, normalize_url
from transport import Transport


class DynamicCrawler:
    def __init__(self, config: ScannerConfig, transport: Transport, state: ScannerState):
        self.config = config
        self.transport = transport
        self.state = state
        self.base_domain = urlparse(config.target_url).netloc.lower()

    def crawl(self) -> List[Page]:
        # Динамический обход собирает то, что реально отрисовал и запросил браузер.
        if not self.transport.browser:
            raise RuntimeError("DynamicCrawler requires browser enabled in config.")

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

            self.transport.browser.reset_observed_requests()
            response = self.transport.request("GET", normalized_url, use_browser=True)
            if response.status_code == 0 or response.status_code >= 400:
                if response.status_code == 0 and response.error:
                    print(f"[!] Dynamic crawl request failed: {normalized_url} ({response.error})")
                elif response.status_code >= 400:
                    print(f"[!] Dynamic crawl HTTP {response.status_code}: {normalized_url}")
                continue

            self.state.mark_visited(normalized_url)

            try:
                self.transport.browser.page.wait_for_load_state("networkidle")
            except Exception:
                pass

            content = self.transport.browser.page.content()
            page = Page(
                url=self.transport.browser.page.url,
                status_code=response.status_code,
                content=content,
                depth=depth,
            )

            soup = BeautifulSoup(content, "html.parser")
            page.links = self.extract_links(soup, page.url)

            input_points: List[InputPoint] = []
            observed_requests: List[ObservedRequest] = []

            navigation_request = build_navigation_request(
                url=page.url,
                source_page_url=page.url,
                source_kind="navigation",
                method="GET",
                status_code=response.status_code,
                headers=response.headers,
            )
            observed_requests.append(navigation_request)
            input_points.extend(extract_query_input_points(navigation_request))

            if self.config.crawler.extract_forms:
                page.forms = self.extract_forms(soup, page.url)
                for form in page.forms:
                    input_points.extend(extract_form_input_points(form))

            browser_requests = self.transport.browser.drain_observed_requests()
            observed_requests.extend(self._build_observed_requests(page.url, browser_requests))
            observed_requests = dedupe_requests(observed_requests)

            for request in observed_requests:
                input_points.extend(extract_query_input_points(request))
                input_points.extend(extract_json_input_points(request))

            page.observed_requests = observed_requests
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
        # Берем реальные ссылки из отрисованного DOM.
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

        if self.config.crawler.extract_js_links:
            for tag in soup.find_all(onclick=True):
                onclick = str(tag.get("onclick", "") or "")
                if "location" not in onclick and "href" not in onclick:
                    continue
                parts = onclick.split("'")
                if len(parts) < 2:
                    continue
                candidate = parts[1]
                if not self.is_good_link(candidate):
                    continue
                absolute = normalize_url(urljoin(base_url, candidate))
                if absolute in seen:
                    continue
                seen.add(absolute)
                links.append(absolute)

        return links

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

              return Array.from(document.forms).map((form, index) => {
                const controls = [];
                const submitControls = [];
                for (const el of Array.from(form.elements)) {
                  if (!el || !el.name || isDisabled(el)) continue;
                  const tag = (el.tagName || "").toLowerCase();
                  const type = ((el.type || tag || "text") + "").toLowerCase();

                  if (tag === "input") {
                    if (["reset", "file", "button"].includes(type)) continue;
                    if (["submit", "image"].includes(type)) {
                      submitControls.push({
                        name: el.name,
                        input_type: type,
                        value: el.value ?? "",
                      });
                      continue;
                    }
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
                    let value = null;
                    if (el.multiple) {
                      value = Array.from(el.selectedOptions || []).map(
                        (option) => option.value || option.text || ""
                      );
                    } else if (el.selectedOptions && el.selectedOptions.length > 0) {
                      value = el.selectedOptions[0].value || el.selectedOptions[0].text || "";
                    } else if (el.options && el.options.length > 0) {
                      value = el.options[0].value || el.options[0].text || "";
                    }
                    controls.push({
                      name: el.name,
                      input_type: el.multiple ? "select-multiple" : "select",
                      value,
                    });
                    continue;
                  }

                  if (tag === "button" && type === "submit") {
                    submitControls.push({
                      name: el.name,
                      input_type: "button:submit",
                      value: el.value || el.textContent || "",
                    });
                  }
                }

                return {
                  dom_index: index,
                  action: form.getAttribute("action") || "",
                  method: (form.getAttribute("method") || "GET").toUpperCase(),
                  enctype: form.getAttribute("enctype") || "application/x-www-form-urlencoded",
                  inputs: controls,
                  submit_controls: submitControls,
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
            submit_controls = [
                InputField(
                    name=str(item.get("name", "")).strip(),
                    input_type=str(item.get("input_type", "submit")).strip(),
                    value=item.get("value"),
                )
                for item in row.get("submit_controls", [])
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
                    submit_controls=submit_controls,
                    dom_index=int(row["dom_index"]) if row.get("dom_index") is not None else None,
                )
            )

        return forms

    def _build_observed_requests(
        self,
        source_page_url: str,
        raw_requests: List[dict],
    ) -> List[ObservedRequest]:
        observed: List[ObservedRequest] = []

        for item in raw_requests:
            method = str(item.get("method", "") or "").upper()
            url = str(item.get("url", "") or "")
            if not method or not url:
                continue

            headers = dict(item.get("headers", {}) or {})
            content_type = str(item.get("content_type", "") or "")
            raw_body = item.get("raw_body")
            form_fields, json_body = parse_request_body(raw_body, content_type)

            observed.append(
                ObservedRequest(
                    source_page_url=source_page_url,
                    source_kind=self._source_kind_for_request(item),
                    method=method,
                    url=url,
                    resource_type=str(item.get("resource_type", "") or ""),
                    content_type=content_type or None,
                    headers=headers,
                    query_params=self._query_params_from_url(url),
                    form_fields=form_fields,
                    json_body=json_body,
                    raw_body=str(raw_body) if raw_body is not None else None,
                )
            )

        return observed

    @staticmethod
    def _source_kind_for_request(item: dict) -> str:
        resource_type = str(item.get("resource_type", "") or "").strip().lower()
        if resource_type in {"xhr", "fetch"}:
            return resource_type
        if resource_type == "document":
            return "navigation"
        return "browser_request"

    @staticmethod
    def _query_params_from_url(url: str) -> dict[str, List[str]]:
        parsed = urlparse(url)
        query = parsed.query
        if not query:
            return {}

        return {
            str(key): [str(value) for value in values]
            for key, values in parse_qs(query).items()
        }

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
