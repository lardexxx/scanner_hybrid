# state.py

from dataclasses import dataclass
from typing import Set, Tuple
from urllib.parse import urlparse, urlunparse


# ===============================
# Normalization Utilities
# ===============================

def normalize_url(url: str) -> str:
    """
    Убираем:
    - фрагменты (#section)
    - лишние слэши
    - приводим схему и хост к lower
    """
    parsed = urlparse(url)

    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment=""
    )

    return urlunparse(normalized)


# ===============================
# Scanner State
# ===============================

@dataclass
class ScannerState:
    max_pages: int

    def __post_init__(self):
        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.tested_forms: Set[Tuple[str, str, str, str]] = set()
        self.tested_params: Set[Tuple[str, str, str, str]] = set()
        self.pages_scanned: int = 0

    # -------------------------------
    # URL management
    # -------------------------------

    def should_visit(self, url: str) -> bool:
        url = normalize_url(url)

        if self.pages_scanned >= self.max_pages:
            return False

        if url in self.visited_urls:
            return False

        return True

    def mark_visited(self, url: str):
        url = normalize_url(url)
        self.visited_urls.add(url)
        self.pages_scanned += 1

    def mark_queued(self, url: str):
        url = normalize_url(url)
        self.queued_urls.add(url)

    def is_queued(self, url: str) -> bool:
        url = normalize_url(url)
        return url in self.queued_urls

    # -------------------------------
    # Form tracking
    # -------------------------------

    def is_form_tested(
        self,
        action: str,
        method: str,
        signature: str = "",
        scope: str = "generic",
    ) -> bool:
        key = (normalize_url(action), method.upper(), signature, scope)
        return key in self.tested_forms

    def mark_form_tested(
        self,
        action: str,
        method: str,
        signature: str = "",
        scope: str = "generic",
    ):
        key = (normalize_url(action), method.upper(), signature, scope)
        self.tested_forms.add(key)

    # -------------------------------
    # Parameter tracking
    # -------------------------------

    def is_param_tested(
        self,
        url: str,
        method: str,
        param: str,
        scope: str = "generic",
    ) -> bool:
        key = (normalize_url(url), method.upper(), param, scope)
        return key in self.tested_params

    def mark_param_tested(
        self,
        url: str,
        method: str,
        param: str,
        scope: str = "generic",
    ):
        key = (normalize_url(url), method.upper(), param, scope)
        self.tested_params.add(key)
