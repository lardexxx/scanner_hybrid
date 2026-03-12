# main.py

import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from config import ScannerConfig
from core import ScannerCore


def save_json_report(result, output_dir: str) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out / f"scan_report_{timestamp}.json"

    # dataclasses -> dict
    data = asdict(result)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return str(filename)


def print_summary(result):
    summary = result.summary()

    print("\n========== SCAN SUMMARY ==========")
    print(f"Target:        {summary['target']}")
    print(f"Pages scanned: {summary['pages_scanned']}")
    print(f"XSS findings:  {summary['xss_count']}")
    print(f"SQLi findings: {summary['sqli_count']}")
    print(f"CSRF findings: {summary['csrf_count']}")
    print("==================================\n")


def print_findings(result, show_evidence: bool = False):

    if result.xss_findings:
        print("---- XSS ----")
        for f in result.xss_findings:
            print(f"[{f.confidence}] {f.method} {f.url} param={f.param} payload={repr(f.payload)} reflected={f.reflected_as}")
            if show_evidence and f.evidence_snippet:
                print(f"  evidence: {f.evidence_snippet[:200]}")
        print()

    if result.sqli_findings:
        print("---- SQLi ----")
        for f in result.sqli_findings:
            print(f"[{f.confidence}] {f.method} {f.url} param={f.param} tech={f.technique} payload={repr(f.payload)}")
            if show_evidence and f.evidence:
                print(f"  evidence: {f.evidence[:200]}")
        print()

    if result.csrf_findings:
        print("---- CSRF ----")
        for f in result.csrf_findings:
            flags = []
            if f.missing_token:
                flags.append("missing_token")
            if f.samesite_issue:
                flags.append("samesite_issue")
            print(f"[{f.confidence}] {f.method} action={f.form_action} from={f.url} flags={','.join(flags) if flags else '-'}")
        print()


def build_config_from_args(args) -> ScannerConfig:
    config = ScannerConfig(
        target_url=args.url,
        use_browser=not args.no_browser,
    )

    # crawler settings
    config.crawler.max_depth = args.depth
    config.crawler.max_pages = args.max_pages
    config.crawler.follow_external = args.follow_external

    # browser settings
    config.browser.headless = not args.show_browser
    config.request.timeout = args.timeout
    config.request.verify_ssl = not args.insecure

    # enable/disable modules
    config.xss.enabled = not args.no_xss
    config.sqli.enabled = not args.no_sqli
    config.csrf.enabled = not args.no_csrf
    config.xss.dom_confirmation_enabled = config.use_browser and config.xss.enabled

    # SQLi delay
    config.sqli.time_based_delay = args.sqli_delay

    return config


def main():
    parser = argparse.ArgumentParser(description="Hybrid Web Vulnerability Scanner (requests + Playwright)")
    parser.add_argument("url", help="Target URL, e.g. http://127.0.0.1:8080/")
    parser.add_argument("--depth", type=int, default=2, help="Crawler max depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=100, help="Crawler max pages (default: 100)")
    parser.add_argument("--follow-external", action="store_true", help="Follow external domains")

    parser.add_argument("--no-browser", action="store_true", help="Disable Playwright (dynamic crawl off)")
    parser.add_argument("--show-browser", action="store_true", help="Run browser in headed mode (not headless)")

    parser.add_argument("--no-xss", action="store_true", help="Disable XSS scanning")
    parser.add_argument("--no-sqli", action="store_true", help="Disable SQLi scanning")
    parser.add_argument("--no-csrf", action="store_true", help="Disable CSRF scanning")

    parser.add_argument("--sqli-delay", type=int, default=5, help="Time-based SQLi delay seconds (default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")

    parser.add_argument("--report-dir", default="reports", help="Directory to save JSON reports (default: reports/)")
    parser.add_argument("--show-evidence", action="store_true", help="Print evidence snippets in console")

    args = parser.parse_args()

    config = build_config_from_args(args)

    scanner = ScannerCore(config)

    try:
        result = scanner.run()
        print_summary(result)
        print_findings(result, show_evidence=args.show_evidence)

        report_path = save_json_report(result, args.report_dir)
        print(f"[+] JSON report saved to: {report_path}")

    finally:
        scanner.shutdown()


if __name__ == "__main__":
    main()
