import re
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup, Comment

from models import ReflectedContext, ReflectionLocation


def detect_locations(marker: str, response_text: str) -> List[ReflectionLocation]:
    soup = BeautifulSoup(response_text, "html.parser")
    seen: set[Tuple[str, str | None, str | None]] = set()
    locations: List[ReflectionLocation] = []

    for node in soup.find_all(string=True):
        text = str(node)
        if marker not in text:
            continue

        parent = node.parent
        if isinstance(node, Comment):
            key = ("comment", parent.name if parent else None, None)
        elif parent and parent.name == "script":
            key = ("script", "script", None)
        else:
            key = ("html_text", parent.name if parent else None, None)
        if key in seen:
            continue
        seen.add(key)
        locations.append(
            ReflectionLocation(
                location_type=key[0],
                tag_name=key[1],
                attribute_name=key[2],
            )
        )

    for tag in soup.find_all(True):
        for attr_name, attr_value in tag.attrs.items():
            if isinstance(attr_value, list):
                value = " ".join(str(v) for v in attr_value)
            else:
                value = str(attr_value)
            if marker not in value:
                continue

            location_type = "event" if attr_name.lower().startswith("on") else "attr"
            key = (location_type, tag.name, attr_name)
            if key in seen:
                continue
            seen.add(key)
            locations.append(
                ReflectionLocation(
                    location_type=location_type,
                    tag_name=tag.name,
                    attribute_name=attr_name,
                )
            )

    if not locations and marker in response_text:
        locations.append(
            ReflectionLocation(
                location_type="html_text",
                tag_name=None,
                attribute_name=None,
            )
        )
    return locations


def derive_contexts(
    response_text: str,
    marker: str,
    coarse_locations: Optional[List[ReflectionLocation]] = None,
) -> List[ReflectedContext]:
    offsets = _find_all_offsets(response_text, marker)
    contexts: List[ReflectedContext] = []
    seen: set[Tuple[int, str, str | None]] = set()

    for offset in offsets:
        ctx = _derive_context_at(response_text, marker, offset)
        if not ctx:
            continue
        key = (ctx.start_offset, ctx.context, ctx.attribute_name)
        if key in seen:
            continue
        seen.add(key)
        contexts.append(ctx)

    if contexts:
        return contexts

    return _fallback_contexts(response_text, marker, coarse_locations or [])


def _derive_context_at(text: str, marker: str, offset: int) -> Optional[ReflectedContext]:
    if _inside_html_comment(text, offset):
        return _make_context("html_comment", marker, None, None, text, offset)

    script_context = _inside_script_context(text, marker, offset)
    if script_context:
        return script_context

    attr_context = _inside_tag_context(text, marker, offset)
    if attr_context:
        return attr_context

    if _inside_html_text(text, offset):
        return _make_context("html_text", marker, None, None, text, offset)

    return None


def _inside_html_comment(text: str, offset: int) -> bool:
    start = text.rfind("<!--", 0, offset)
    if start == -1:
        return False
    end = text.rfind("-->", 0, offset)
    return end < start


def _inside_script_context(text: str, marker: str, offset: int) -> Optional[ReflectedContext]:
    lower = text.lower()
    script_open = lower.rfind("<script", 0, offset)
    if script_open == -1:
        return None

    open_tag_end = text.find(">", script_open)
    if open_tag_end == -1 or open_tag_end >= offset:
        return None

    script_close = lower.find("</script", open_tag_end)
    if script_close == -1 or offset >= script_close:
        return None

    js_start = open_tag_end + 1
    js_pos = offset - js_start
    js_code = text[js_start:script_close]
    js_context = _determine_js_context(js_code, js_pos)

    return _make_context(js_context, marker, "script", None, text, offset)


def _inside_tag_context(text: str, marker: str, offset: int) -> Optional[ReflectedContext]:
    lt = text.rfind("<", 0, offset)
    gt = text.find(">", lt if lt >= 0 else 0)
    if lt == -1 or gt == -1 or not (lt < offset < gt):
        return None

    tag_fragment = text[lt : gt + 1]
    tag_name_match = re.match(r"<\s*([a-zA-Z0-9:-]+)", tag_fragment)
    tag_name = tag_name_match.group(1).lower() if tag_name_match else None

    attr_pattern = re.compile(
        r"([^\s=<>'\"/]+)\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
        re.DOTALL,
    )

    for match in attr_pattern.finditer(tag_fragment):
        attr_name = match.group(1)
        if match.group(3) is not None:
            value_start = lt + match.start(3)
            value_end = lt + match.end(3)
        elif match.group(4) is not None:
            value_start = lt + match.start(4)
            value_end = lt + match.end(4)
        else:
            value_start = lt + match.start(5)
            value_end = lt + match.end(5)

        if not (value_start <= offset < value_end):
            continue

        context = "event" if attr_name.lower().startswith("on") else "attr"
        return _make_context(context, marker, tag_name, attr_name, text, offset)

    return None


def _inside_html_text(text: str, offset: int) -> bool:
    prev_gt = text.rfind(">", 0, offset)
    prev_lt = text.rfind("<", 0, offset)
    return prev_gt > prev_lt


def _determine_js_context(js: str, pos: int) -> str:
    state = "raw"
    escaped = False
    i = 0

    while i < min(pos, len(js)):
        ch = js[i]
        nxt = js[i + 1] if i + 1 < len(js) else ""

        if state in {"sq", "dq", "template"}:
            if escaped:
                escaped = False
                i += 1
                continue
            if ch == "\\":
                escaped = True
                i += 1
                continue
            if state == "sq" and ch == "'":
                state = "raw"
            elif state == "dq" and ch == "\"":
                state = "raw"
            elif state == "template" and ch == "`":
                state = "raw"
            i += 1
            continue

        if ch == "'":
            state = "sq"
            i += 1
            continue
        if ch == "\"":
            state = "dq"
            i += 1
            continue
        if ch == "`":
            state = "template"
            i += 1
            continue

        # Skip comments compactly without storing separate contexts.
        if ch == "/" and nxt == "/":
            line_end = js.find("\n", i + 2)
            i = len(js) if line_end == -1 else line_end + 1
            continue
        if ch == "/" and nxt == "*":
            block_end = js.find("*/", i + 2)
            i = len(js) if block_end == -1 else block_end + 2
            continue

        i += 1

    if state == "sq":
        return "js_string_sq"
    if state == "dq":
        return "js_string_dq"
    if state == "template":
        return "js_template"
    return "js_raw"


def _fallback_contexts(
    text: str,
    marker: str,
    coarse_locations: List[ReflectionLocation],
) -> List[ReflectedContext]:
    mapping = {
        "html_text": "html_text",
        "comment": "html_comment",
        "script": "js_raw",
        "attr": "attr",
        "event": "event",
    }

    fallback_offset = text.find(marker)
    contexts: List[ReflectedContext] = []

    for loc in coarse_locations:
        context = mapping.get(loc.location_type)
        if not context:
            continue
        contexts.append(
            ReflectedContext(
                context=context,
                marker=marker,
                tag_name=loc.tag_name,
                attribute_name=loc.attribute_name,
                quote_type=None,
                snippet=_snippet(text, fallback_offset),
                start_offset=max(0, fallback_offset),
            )
        )

    return contexts


def _make_context(
    context: str,
    marker: str,
    tag_name: Optional[str],
    attribute_name: Optional[str],
    text: str,
    offset: int,
) -> ReflectedContext:
    return ReflectedContext(
        context=context,
        marker=marker,
        tag_name=tag_name,
        attribute_name=attribute_name,
        quote_type=None,
        snippet=_snippet(text, offset),
        start_offset=offset,
    )


def _find_all_offsets(text: str, marker: str) -> List[int]:
    offsets: List[int] = []
    start = 0
    while True:
        idx = text.find(marker, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + max(1, len(marker))
    return offsets


def _snippet(text: str, offset: int, window: int = 200) -> str:
    if offset < 0:
        offset = 0
    start = max(0, offset - window)
    end = min(len(text), offset + window)
    return text[start:end].replace("\n", " ").replace("\r", " ")
